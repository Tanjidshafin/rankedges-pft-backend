/**
 * Low-rate Firestore progress updates during MetaApi sync to avoid RESOURCE_EXHAUSTED.
 */

const MIN_INTERVAL_MS = Math.max(500, Number(process.env.SYNC_PROGRESS_MIN_INTERVAL_MS || 2500));

/** @typedef {{ phase: string, lastAt: number }} PhaseThrottleBucket */

/** @type {Map<string, PhaseThrottleBucket>} */
const accountThrottle = new Map();

/** Per (bulk account slice, phase): last write — avoids collapsing multi-account Sync All into one stale row */
/** @type {Map<string, { lastAt: number }>} */
const bulkThrottleByKey = new Map();

function shouldSkipSamePhaseThrottle(map, key, phase) {
  const prev = map.get(key);
  const now = Date.now();
  if (!prev) return false;
  if (phase !== prev.phase) return false;
  return now - prev.lastAt < MIN_INTERVAL_MS;
}

function bumpPhase(map, key, phase) {
  map.set(key, { phase, lastAt: Date.now() });
}

function shouldSkipBulkKey(key) {
  const prev = bulkThrottleByKey.get(key);
  const now = Date.now();
  if (!prev) return false;
  return now - prev.lastAt < MIN_INTERVAL_MS;
}

function bumpBulkKey(key) {
  bulkThrottleByKey.set(key, { lastAt: Date.now() });
}

function bulkThrottleKey(payload, phase) {
  const raw = payload?.currentAccountId;
  const accountKey =
    raw !== undefined && raw !== null && String(raw).length > 0 ? String(raw) : '*';
  return `${accountKey}:${phase}`;
}

/**
 * Progress on tradingAccounts.{id}; throttled unless phase changes from last flushed phase.
 */
async function reportAccountSyncProgressThrottled(db, collections, accountDocId, phase, message, extra, omitUndefined) {
  if (!accountDocId) return;
  const key = String(accountDocId);
  if (shouldSkipSamePhaseThrottle(accountThrottle, key, phase)) {
    return;
  }
  bumpPhase(accountThrottle, key, phase);

  try {
    const payload = omitUndefined({
      metaapi_sync_progress: {
        phase,
        message,
        updatedAt: new Date().toISOString(),
        ...extra,
      },
      ...(phase === 'starting' ? { metaapi_sync_status: 'running', metaapi_sync_error: null } : {}),
    });
    await db.collection(collections.accounts).doc(key).set(payload, { merge: true });
  } catch (err) {
    console.warn('[MetaApi sync] account progress failed:', err instanceof Error ? err.message : err);
  }
}

async function flushAccountThrottleNow(db, collections, accountDocId, phase, message, extra, omitUndefined) {
  const key = String(accountDocId);
  bumpPhase(accountThrottle, key, phase);
  await db
    .collection(collections.accounts)
    .doc(key)
    .set(
      omitUndefined({
        metaapi_sync_progress: {
          phase,
          message,
          updatedAt: new Date().toISOString(),
          ...extra,
        },
        ...(phase === 'starting' ? { metaapi_sync_status: 'running', metaapi_sync_error: null } : {}),
      }),
      { merge: true },
    );
}

function forgetAccountThrottleState(accountDocId) {
  if (accountDocId) accountThrottle.delete(String(accountDocId));
}

async function clearAccountSyncProgress(db, collections, omitUndefinedFields, accountDocId) {
  if (!accountDocId) return;
  try {
    accountThrottle.delete(String(accountDocId));
    await db
      .collection(collections.accounts)
      .doc(String(accountDocId))
      .set(omitUndefinedFields({ metaapi_sync_progress: null }), { merge: true });
  } catch (_) {
    /* empty */
  }
}

/** metaApiAdminSyncProgress/current — throttled within the same phase for the same currentAccountId */
async function reportAdminBulkSyncProgressThrottled(db, collections, bulkDocId, payload) {
  const phase = String(payload.phase || '');
  const tKey = bulkThrottleKey(payload, phase);
  if (shouldSkipBulkKey(tKey)) {
    return;
  }
  bumpBulkKey(tKey);

  try {
    await db
      .collection(collections.metaApiAdminSyncProgress)
      .doc(bulkDocId)
      .set(
        {
          active: payload.active !== false,
          updatedAt: new Date().toISOString(),
          ...payload,
        },
        { merge: true },
      );
  } catch (err) {
    console.warn('[MetaApi sync] bulk progress failed:', err instanceof Error ? err.message : err);
  }
}

async function clearAdminBulkSyncProgress(db, collections, bulkDocId) {
  bulkThrottleByKey.clear();
  try {
    await db
      .collection(collections.metaApiAdminSyncProgress)
      .doc(bulkDocId)
      .set(
        {
          active: false,
          message: 'Idle',
          phase: 'idle',
          updatedAt: new Date().toISOString(),
        },
        { merge: true },
      );
  } catch (_) {
    /* empty */
  }
}

module.exports = {
  MIN_INTERVAL_MS,
  reportAccountSyncProgressThrottled,
  flushAccountThrottleNow,
  forgetAccountThrottleState,
  clearAccountSyncProgress,
  reportAdminBulkSyncProgressThrottled,
  clearAdminBulkSyncProgress,
};
