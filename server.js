require('dotenv').config()
const express = require('express');
const cors = require('cors');
const cron = require('node-cron');
const admin = require('firebase-admin');
const {
  fetchMetaApiHistoryDealsPaginated,
  deriveSyncedMetricsPackage,
  fetchMetaApiHistoryDealsFullRange,
  deriveMetricsFromFirestoreTradeDocs,
} = require('./metaApiDealUtils');
const {
  fetchMetaStatsMetrics,
  mapMetaStatsToAccountMetrics,
  isMetaStatsActivityEmpty,
  mergeActivityMetricsInto,
  safeJsonSnippet,
  unwrapMetaStatsMetricsBody,
  slimMetaStatsForStorage,
  normalizeDailyGrowthSeries,
  sanitizeDailyGrowthSeriesForFirestore,
  MetaStatsFetchError,
} = require('./metaApiMetaStats');
const {
  enableMetaStatsForAccount,
  deployProvisioningAccount,
  waitForProvisioningDeployed,
} = require('./metaApiProvisioningFeatures');
const { formatMetaApiHttpError } = require('./metaApiHttpErrors');
const { assertMetaApiCloudAccountId } = require('./metaApiProvisioningId');
const {
  reportAccountSyncProgressThrottled,
  flushAccountThrottleNow,
  forgetAccountThrottleState,
  reportAdminBulkSyncProgressThrottled,
  clearAdminBulkSyncProgress: clearAdminBulkSyncProgressDoc,
} = require('./syncProgressReporter');
const { createAchievementEngine, DEFINITION_BY_ID } = require('./achievementEngine');
const { createNotificationAdmin } = require('./notificationAdmin');
const { scheduleContestLifecycleCron } = require('./contestLifecycle');
const { startContestAdmin } = require('./contestStart');
const {
  mapPftParticipantStatusToContest,
  rankPftLeaderboardEntries,
  buildPftLeaderboardFields,
  sanitizePftLeaderboardFields,
} = require('./pftScoring');

const METAAPI_TRADES_FULL = 'full';
const METAAPI_TRADES_METRICS_ONLY = 'metrics_only';

function normalizeTradesMode(value) {
  const v = String(value || '').toLowerCase();
  if (v === METAAPI_TRADES_METRICS_ONLY) return METAAPI_TRADES_METRICS_ONLY;
  return METAAPI_TRADES_FULL;
}

/** Per-request/run trades persistence (documents in metaApiTrades/metaApiPositions). */
function resolveTradesMode(requestedBy, options = {}) {
  if (options.tradesMode) return normalizeTradesMode(options.tradesMode);

  const allRaw = process.env.METAAPI_SYNC_ALL_TRADES_MODE;
  const bulkAllExplicit =
    allRaw !== undefined && String(allRaw).trim() !== ''
      ? normalizeTradesMode(allRaw)
      : undefined;

  if (requestedBy === 'admin_manual' && options.bulkSyncAll === true) {
    if (bulkAllExplicit === METAAPI_TRADES_FULL || bulkAllExplicit === METAAPI_TRADES_METRICS_ONLY) return bulkAllExplicit;
    return METAAPI_TRADES_METRICS_ONLY;
  }

  if (requestedBy === 'admin_manual' && options.bulkSyncAll !== true) {
    return METAAPI_TRADES_FULL;
  }

  // Owner connect / POST /api/meta-api/sync-account — default metrics-only so connect does not exhaust Spark daily writes.
  if (requestedBy === 'user_ui') {
    const uiRaw = process.env.METAAPI_SYNC_USER_UI_TRADES_MODE;
    const uiExplicit =
      uiRaw !== undefined && String(uiRaw).trim() !== ''
        ? normalizeTradesMode(uiRaw)
        : undefined;
    if (uiExplicit === METAAPI_TRADES_FULL || uiExplicit === METAAPI_TRADES_METRICS_ONLY) return uiExplicit;
    return METAAPI_TRADES_METRICS_ONLY;
  }

  const global = normalizeTradesMode(process.env.METAAPI_SYNC_TRADES_MODE || METAAPI_TRADES_FULL);
  return global === METAAPI_TRADES_METRICS_ONLY ? METAAPI_TRADES_METRICS_ONLY : METAAPI_TRADES_FULL;
}
const app = express();
const PORT = Number(process.env.PORT || 3001);
const DEFAULT_TOP_200_SIZE = 200;
const CAPTURE_LOCK_STALE_MS = Number(process.env.PFT_CAPTURE_LOCK_STALE_MS || 2 * 60 * 60 * 1000);
const INTERNAL_CRON_ENABLED = String(process.env.PFT_CRON_ENABLED || 'false').toLowerCase() === 'true';
const INTERNAL_CRON_TIMEZONE = process.env.PFT_CRON_TIMEZONE || 'UTC';
const INTERNAL_CRON_SYNC_SCHEDULE = process.env.PFT_CRON_SYNC_SCHEDULE || '0 0,12 * * *';
const INTERNAL_CRON_CAPTURE_SCHEDULE = process.env.PFT_CRON_CAPTURE_SCHEDULE || '5 0 * * *';
const INTERNAL_CRON_PFT_LIVE_SCHEDULE = process.env.PFT_CRON_LIVE_SCHEDULE || '*/30 * * * *';
const ACHIEVEMENT_CRON_ENABLED =
  process.env.ACHIEVEMENT_CRON_ENABLED !== undefined
    ? String(process.env.ACHIEVEMENT_CRON_ENABLED).toLowerCase() === 'true'
    : INTERNAL_CRON_ENABLED;
const ACHIEVEMENT_CRON_SCHEDULE = process.env.ACHIEVEMENT_CRON_SCHEDULE || '0 0 * * *';
const ACHIEVEMENT_CRON_TIMEZONE =
  process.env.ACHIEVEMENT_CRON_TIMEZONE || INTERNAL_CRON_TIMEZONE;
const ACHIEVEMENT_CRON_CONCURRENCY = Math.max(
  1,
  Math.min(Number(process.env.ACHIEVEMENT_CRON_CONCURRENCY) || 5, 20),
);
const ACHIEVEMENT_CRON_PAGE_SIZE = Math.max(
  50,
  Math.min(Number(process.env.ACHIEVEMENT_CRON_PAGE_SIZE) || 200, 500),
);

const schedulerState = {
  syncRunning: false,
  captureRunning: false,
  pftLiveRunning: false,
  achievementCronRunning: false,
};
function initializeFirebaseAdmin() {
  if (admin.apps.length > 0) return;
  const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (serviceAccountJson) {
    let parsed;
    try {
      parsed = JSON.parse(serviceAccountJson);
    } catch (error) {
      throw new Error(
        'Invalid FIREBASE_SERVICE_ACCOUNT_JSON. In backend/.env it must be a single-line JSON string, or use FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, and FIREBASE_PRIVATE_KEY instead.',
      );
    }
    admin.initializeApp({
      credential: admin.credential.cert(parsed),
    });
    return;
  }

  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n');

  if (projectId && clientEmail && privateKey) {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId,
        clientEmail,
        privateKey,
      }),
    });
    return;
  }

  admin.initializeApp();
}

initializeFirebaseAdmin();

const db = admin.firestore();
db.settings({ ignoreUndefinedProperties: true });
const FieldValue = admin.firestore.FieldValue;

function pftLeaderboardPayload(fields, extra = {}) {
  return omitUndefinedFirestoreFields({
    ...sanitizePftLeaderboardFields(fields),
    ...extra,
  });
}

const DEFAULT_DEV_ORIGINS = [
  'http://localhost:8080',
  'http://127.0.0.1:8080',
  'http://localhost:5173',
  'http://127.0.0.1:5173',
];

function getAllowedOrigins() {
  const configured = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);

  return [...new Set([...configured, ...DEFAULT_DEV_ORIGINS])];
}

const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = getAllowedOrigins();
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
      return;
    }
    callback(new Error('Origin not allowed by CORS.'));
  },
  credentials: true,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '2mb' }));

app.use((req, _res, next) => {
  if (req.path.startsWith('/api/')) {
    console.log(`[http] ${req.method} ${req.path}`);
  }
  next();
});

const COLLECTIONS = {
  users: 'users',
  settings: 'settings',
  programs: 'pftPrograms',
  batches: 'pftBatches',
  participants: 'pftBatchParticipants',
  snapshots: 'pftBatchSnapshots',
  top200: 'pftTop200',
  top200History: 'pftTop200History',
  jobs: 'pftCaptureJobs',
  accounts: 'tradingAccounts',
  metaApiAccountSnapshots: 'metaApiAccountSnapshots',
  metaApiTrades: 'metaApiTrades',
  metaApiPositions: 'metaApiPositions',
  metaApiSyncRuns: 'metaApiSyncRuns',
  metaApiAdminSyncProgress: 'metaApiAdminSyncProgress',
  leaderboard: 'leaderboard',
  contests: 'contests',
  prizePayouts: 'prizePayouts',
  scamAlerts: 'scamAlerts',
  reviews: 'reviews',
  contestParticipations: 'contestParticipations',
  userAchievements: 'userAchievements',
  notifications: 'notifications',
};

const ADMIN_SYNC_PROGRESS_DOC_ID = 'current';

const ACHIEVEMENT_ENGINE_COLLECTIONS = {
  users: COLLECTIONS.users,
  tradingAccounts: COLLECTIONS.accounts,
  leaderboard: COLLECTIONS.leaderboard,
  prizePayouts: COLLECTIONS.prizePayouts,
  scamAlerts: COLLECTIONS.scamAlerts,
  reviews: COLLECTIONS.reviews,
  contestParticipations: COLLECTIONS.contestParticipations,
  metaApiTrades: COLLECTIONS.metaApiTrades,
  userAchievements: COLLECTIONS.userAchievements,
};

const achievementEngine = createAchievementEngine(db, ACHIEVEMENT_ENGINE_COLLECTIONS);
const notificationAdmin = createNotificationAdmin(db, {
  users: COLLECTIONS.users,
  notifications: COLLECTIONS.notifications,
});

const SETTINGS_DOC_ID = 'site_settings';

function toIsoDate(value) {
  if (!value) return '';
  if (typeof value === 'string') return value;
  if (typeof value.toDate === 'function') return value.toDate().toISOString();
  return String(value);
}

function maskAccountReference(accountId) {
  if (!accountId) return 'N/A';
  if (accountId.length <= 4) return accountId;
  return `${accountId.slice(0, 2)}****${accountId.slice(-2)}`;
}

function isKnownTradingPlatform(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return normalized === 'mt4' || normalized === 'mt5';
}

function shouldReplaceTradingPlatform(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return !normalized || normalized === 'unknown';
}

function inferTradingPlatformFromServer(server) {
  const normalized = String(server || '').toLowerCase();
  if (!normalized) return null;
  if (normalized.includes('mt4') || normalized.includes('metatrader 4') || normalized.includes('metatrader4')) {
    return 'mt4';
  }
  if (normalized.includes('mt5') || normalized.includes('metatrader 5') || normalized.includes('metatrader5')) {
    return 'mt5';
  }
  return null;
}

function resolveTradingAccountPlatform(account, participant, snapshot) {
  for (const candidate of [
    participant?.platform,
    account?.platform,
    snapshot?.platform,
    account?.metaapi_platform,
  ]) {
    if (isKnownTradingPlatform(candidate)) {
      return String(candidate).trim().toLowerCase();
    }
  }

  const inferred = inferTradingPlatformFromServer(account?.server);
  if (inferred) return inferred;

  return 'unknown';
}

async function getSiteSettings() {
  const snap = await db.collection(COLLECTIONS.settings).doc(SETTINGS_DOC_ID).get();
  return snap.exists ? snap.data() : {};
}

async function updateSiteSettings(partial) {
  await db.collection(COLLECTIONS.settings).doc(SETTINGS_DOC_ID).set(partial, { merge: true });
}

async function requireUser(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!token) {
      res.status(401).json({ error: 'Missing Firebase ID token.' });
      return;
    }

    const decoded = await admin.auth().verifyIdToken(token);
    req.firebaseUser = { uid: decoded.uid, email: decoded.email || '' };
    next();
  } catch (error) {
    res.status(401).json({ error: error instanceof Error ? error.message : 'Invalid auth token.' });
  }
}

function profileHasAdminPermission(profile, permission) {
  if (!profile || profile.role !== 'admin') return false;
  const tier = profile.adminTier || 'full';
  if (tier === 'super' || tier === 'full') return true;
  const perms = profile.adminPermissions || [];
  if (perms.includes('*')) return true;
  return perms.includes(permission);
}

function requireAdminPermission(permission) {
  return async (req, res, next) => {
    try {
      const authHeader = req.headers.authorization || '';
      const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
      if (!token) {
        res.status(401).json({ error: 'Missing Firebase ID token.' });
        return;
      }

      const decoded = await admin.auth().verifyIdToken(token);
      const userSnap = await db.collection(COLLECTIONS.users).doc(decoded.uid).get();
      if (!userSnap.exists || userSnap.data().role !== 'admin') {
        res.status(403).json({ error: 'Admin access required.' });
        return;
      }

      if (!profileHasAdminPermission(userSnap.data(), permission)) {
        res.status(403).json({ error: `Admin permission required: ${permission}` });
        return;
      }

      req.user = {
        uid: decoded.uid,
        email: decoded.email || '',
        profile: userSnap.data(),
      };
      next();
    } catch (error) {
      res.status(401).json({ error: error instanceof Error ? error.message : 'Invalid auth token.' });
    }
  };
}

async function requireAdmin(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!token) {
      res.status(401).json({ error: 'Missing Firebase ID token.' });
      return;
    }

    const decoded = await admin.auth().verifyIdToken(token);
    const userSnap = await db.collection(COLLECTIONS.users).doc(decoded.uid).get();
    if (!userSnap.exists || userSnap.data().role !== 'admin') {
      res.status(403).json({ error: 'Admin access required.' });
      return;
    }

    req.user = {
      uid: decoded.uid,
      email: decoded.email || '',
      profile: userSnap.data(),
    };
    next();
  } catch (error) {
    res.status(401).json({ error: error instanceof Error ? error.message : 'Invalid auth token.' });
  }
}

function requireCronSecret(req, res, next) {
  const expected = process.env.CRON_SECRET;
  if (!expected) {
    res.status(500).json({ error: 'CRON_SECRET is not configured.' });
    return;
  }

  const provided = req.headers['x-cron-secret'];
  if (provided !== expected) {
    res.status(403).json({ error: 'Invalid cron secret.' });
    return;
  }
  next();
}

function resolveMetaApiTokenCandidates(account, settings) {
  const candidates = [
    account?.metaapi_token,
    process.env.METAAPI_TOKEN,
    settings?.metaapi_token,
  ].filter(Boolean);

  return [...new Set(candidates)];
}

function isMetaApiAuthError(error) {
  const message = String(error instanceof Error ? error.message : error || '').toLowerCase();
  return message.includes('401') || message.includes('403');
}

async function requestMetaApiAccountDetailsWithTokens(accountId, tokens) {
  let lastError;

  for (const token of tokens) {
    try {
      const data = await fetchMetaApiAccountDetails(accountId, token);
      return { token, data };
    } catch (error) {
      lastError = error;
      if (!isMetaApiAuthError(error)) {
        throw error;
      }
    }
  }

  throw lastError || new Error('MetaApi account-details request failed with authorization error.');
}

async function getMetaApiAccountInfo(account) {
  const settings = await getSiteSettings();
  const tokenCandidates = resolveMetaApiTokenCandidates(account, settings);
  if (!account.metaapi_account_id || tokenCandidates.length === 0) {
    throw new Error(`MetaApi credentials missing for account ${account.login || account.id || account.metaapi_account_id}.`);
  }

  const { token, data: regionPayload } = await requestMetaApiAccountDetailsWithTokens(
    account.metaapi_account_id,
    tokenCandidates,
  );
  assertProvisioningReadyForClientApi(regionPayload, account.metaapi_account_id);
  const region = resolveMetaApiHostedRegion(regionPayload, account);
  return fetchMetaApiAccountInfo(account, token, region);
}

function isTransientMetaApiError(error) {
  const message = String(error instanceof Error ? error.message : error || '').toLowerCase();
  return [
    '429',
    '408',
    '500',
    '502',
    '503',
    '504',
    'timeout',
    'network',
    'temporar',
  ].some((token) => message.includes(token));
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function chunkArray(items, size) {
  const chunks = [];
  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size));
  }
  return chunks;
}

async function deleteDocumentsByField(collectionName, fieldName, fieldValue) {
  const snapshot = await db.collection(collectionName).where(fieldName, '==', fieldValue).get();
  if (snapshot.empty) return 0;

  let deleted = 0;
  const chunks = chunkArray(snapshot.docs, 400);
  for (const chunk of chunks) {
    const batch = db.batch();
    chunk.forEach((docSnap) => batch.delete(docSnap.ref));
    await batch.commit();
    deleted += chunk.length;
  }

  return deleted;
}

async function writeDocuments(collectionName, docs) {
  if (docs.length === 0) return;
  const maxPerSec = Math.max(10, Number(process.env.FIRESTORE_MAX_WRITES_PER_SEC || 200));

  const bulkWriter = db.bulkWriter({
    throttling: {
      initialOpsPerSecond: maxPerSec,
      maxOpsPerSecond: maxPerSec,
    },
  });

  bulkWriter.onWriteError((error) => {
    console.warn(
      '[Firestore][BulkWriter]',
      error.code,
      error.message,
      'attempt',
      error.failedAttempts,
    );
    return Number(error.failedAttempts || 0) < 15;
  });

  const colRef = db.collection(collectionName);
  try {
    for (const doc of docs) {
      bulkWriter.set(colRef.doc(String(doc.id)), omitUndefinedFirestoreFields(doc.data), { merge: false });
    }
    await bulkWriter.close();
  } catch (error) {
    console.error('[Firestore][BulkWriter] fatal:', error instanceof Error ? error.message : error);
    throw error;
  }
}

/** Firestore rejects `undefined` at any depth (including array elements). */
function omitUndefinedFirestoreFields(obj) {
  if (obj === undefined) return undefined;
  if (obj === null) return null;
  if (Array.isArray(obj)) {
    return obj.map((item) => omitUndefinedFirestoreFields(item));
  }
  if (obj instanceof Date) return obj;
  if (typeof obj !== 'object') return obj;

  const ctorName = obj.constructor?.name;
  if (ctorName && ctorName !== 'Object') {
    return obj;
  }

  const out = {};
  for (const key of Object.keys(obj)) {
    const v = obj[key];
    if (v === undefined) continue;
    out[key] = omitUndefinedFirestoreFields(v);
  }
  return out;
}

async function fetchMetaApiAccountDetails(accountId, token) {
  const response = await fetch(`https://mt-provisioning-api-v1.agiliumtrade.agiliumtrade.ai/users/current/accounts/${accountId}`, {
    headers: {
      'auth-token': token,
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(
      await formatMetaApiHttpError('account-details (provisioning)', response, { accountId }),
    );
  }

  return response.json();
}

function getClientApiUrl(region = 'new-york') {
  return `https://mt-client-api-v1.${region}.agiliumtrade.ai`;
}

/** Prefer region from provisioning API — wrong region causes timeouts / wrong-datacenter URLs. */
function resolveMetaApiHostedRegion(regionPayload, account) {
  const fromProvisioning =
    regionPayload && typeof regionPayload.region === 'string' && regionPayload.region.trim()
      ? regionPayload.region.trim()
      : '';
  const fromDoc =
    account && typeof account.metaapi_region === 'string' && account.metaapi_region.trim()
      ? account.metaapi_region.trim()
      : '';
  return fromProvisioning || fromDoc || 'new-york';
}

/** Fast-fail with actionable messaging before hammering RPC that often 504s. */
function assertProvisioningReadyForClientApi(provisioningPayload, metaapiAccountId) {
  if (!provisioningPayload || typeof provisioningPayload !== 'object') return;

  const { state } = provisioningPayload;
  const connectionStatus =
    provisioningPayload.connectionStatus ?? provisioningPayload.connection_status;
  const masked = metaapiAccountId ? maskAccountReference(metaapiAccountId) : '';
  const stateNormalized = typeof state === 'string' ? state.toUpperCase() : '';

  if (stateNormalized === 'DEPLOY_FAILED') {
    throw new Error(
      `MetaApi deployment failed for ${masked}; fix or redeploy this account in MetaApi Cloud before syncing.`,
    );
  }

  if (stateNormalized === 'DEPLOYING') {
    throw new Error(
      `MetaApi account ${masked} is still deploying (state=${state}). Wait until the dashboard shows DEPLOYED, then sync again.`,
    );
  }

  if (typeof connectionStatus === 'string' && connectionStatus.toUpperCase() === 'DISCONNECTED') {
    throw new Error(
      `MetaApi broker RPC is disconnected for ${masked}. Keep MetaTrader logged in to your broker so the EA/connector can reach the terminal; retry sync after MetaApi shows a connected state.`,
    );
  }
}

/**
 * Prefer cached/light client API calls before refreshTerminalState=true (often 504s when broker RPC is busy).
 */
async function fetchMetaApiAccountInfo(account, token, region) {
  const resolvedRegion =
    (typeof region === 'string' && region.trim()) || account.metaapi_region || 'new-york';
  const clientApiUrl = getClientApiUrl(resolvedRegion);
  const base = `${clientApiUrl}/users/current/accounts/${account.metaapi_account_id}/account-information`;
  const headers = {
    'auth-token': token,
    'Content-Type': 'application/json',
  };
  const transient = new Set([504, 408, 502, 503]);
  const extras = { region: resolvedRegion, accountId: account.metaapi_account_id };

  async function fetchWithTransientRetries(label, href, maxAttempts) {
    let lastTransientSummary = '';
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      if (attempt > 0) await delay(2500 + attempt * 500);
      const response = await fetch(href, { headers });
      if (response.ok) {
        return { ok: true, data: await response.json() };
      }
      const summary = await formatMetaApiHttpError(label, response, extras);
      if (!transient.has(response.status)) {
        throw new Error(summary);
      }
      lastTransientSummary = summary;
    }
    return { ok: false, summary: lastTransientSummary };
  }

  const phases = [
    { label: 'account-information (cached snapshot)', href: base, tries: 5 },
    {
      label: 'account-information (?refreshTerminalState=false)',
      href: `${base}?refreshTerminalState=false`,
      tries: 3,
    },
    {
      label: 'account-information (refreshTerminalState=true)',
      href: `${base}?refreshTerminalState=true`,
      tries: 3,
    },
  ];

  const failed = [];
  for (const phase of phases) {
    const outcome = await fetchWithTransientRetries(phase.label, phase.href, phase.tries);
    if (outcome.ok) return outcome.data;
    failed.push(outcome.summary);
  }

  throw new Error(
    [
      'MetaApi timed out repeatedly on account-information (all phases). This almost always means the hosted terminal broker link is unavailable or overloaded.',
      '',
      'Checks: MetaTrader stays logged into the broker matching this account; leave the MetaApi EA/connector running; confirm MetaApi Cloud lists this account as DEPLOYED; fix billing/credits if MetaApi shows quota warnings.',
      '',
      `[region: ${resolvedRegion}] [MetaApi account: ${account.metaapi_account_id}]`,
      '[Last phase summaries below]',
      ...failed.map((line, idx) => `  (${idx + 1}) ${line}`),
    ].join('\n'),
  );
}

async function loadFirestoreTradesForAccount(userId, accountKey, metaapiCloudAccountId, login) {
  const candidates = [
    ...new Set(
      [accountKey, metaapiCloudAccountId, login].filter((v) => typeof v === 'string' && String(v).trim()),
    ),
  ];
  const byDocId = new Map();
  for (const accountId of candidates) {
    const snap = await db
      .collection(COLLECTIONS.metaApiTrades)
      .where('user_id', '==', userId)
      .where('account_id', '==', accountId)
      .get();
    for (const docSnap of snap.docs) {
      byDocId.set(docSnap.id, { id: docSnap.id, ...docSnap.data() });
    }
  }
  return Array.from(byDocId.values());
}

async function fetchMetaApiTrades(account, token, startTime, endTime, region, onProgress) {
  const resolvedRegion = region || account.metaapi_region || 'new-york';
  const clientApiUrl = getClientApiUrl(resolvedRegion);
  const start = startTime || new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
  const end = endTime || new Date().toISOString();
  return fetchMetaApiHistoryDealsPaginated(
    clientApiUrl,
    account.metaapi_account_id,
    token,
    start,
    end,
    onProgress,
  );
}

async function fetchMetaApiPositions(account, token, region) {
  const resolvedRegion = region || account.metaapi_region || 'new-york';
  const clientApiUrl = getClientApiUrl(resolvedRegion);
  const response = await fetch(
    `${clientApiUrl}/users/current/accounts/${account.metaapi_account_id}/positions`,
    {
      headers: {
        'auth-token': token,
        'Content-Type': 'application/json',
      },
    },
  );

  if (!response.ok) {
    throw new Error(
      await formatMetaApiHttpError('positions', response, {
        region: resolvedRegion,
        accountId: account.metaapi_account_id,
      }),
    );
  }

  return response.json();
}

async function fetchMetaStatsWithProvisioningRecovery(metaapiCloudAccountId, token, region) {
  try {
    return await fetchMetaStatsMetrics(metaapiCloudAccountId, token, region, {
      includeOpenPositions: true,
    });
  } catch (err) {
    const snippet = `${err.bodyText} ${err.message}`;
    const isForbiddenMetaStats =
      err instanceof MetaStatsFetchError &&
      err.status === 403 &&
      /\benable-account-features|enable.?metastats|metastatsapi|ForbiddenError|"forbiddenerror"|metastats api\b/i.test(
        snippet,
      );

    if (!isForbiddenMetaStats) {
      console.error('[MetaStats][error]', err);
      throw err;
    }

    console.error(
      '[MetaStats][recovery] HTTP 403 from MetaStats (full MetaApi body for debugging):',
      typeof err.bodyText === 'string' ? err.bodyText : String(err.bodyText || ''),
    );

    const en = await enableMetaStatsForAccount(metaapiCloudAccountId, token);
    if (!(en.ok || en.status === 204)) {
      console.error('[MetaStats][recovery] provision enable-metastats-api failed:', en.status, en.text);
      throw new Error(
        `MetaStats is disabled on this MetaApi account (${en.status}). ${en.text.slice(0, 800)} Enable MetaStats in MetaApi Cloud (account → features), ensure billing allows it (paid option), then sync again.`,
      );
    }

    const deployRes = await deployProvisioningAccount(metaapiCloudAccountId, token);
    if (!deployRes.ok) {
      console.warn(
        '[MetaStats][recovery] Provision deploy HTTP',
        deployRes.status,
        deployRes.text.slice(0, 500),
      );
    }

    const deployed = await waitForProvisioningDeployed(metaapiCloudAccountId, token);
    if (!deployed) {
      throw new Error(
        'MetaStats was enabled in MetaApi; the account is still redeploying. Wait 60–120 seconds, then retry connect or Admin → Sync.',
      );
    }

    console.log('[MetaStats][recovery] Retrying metastats metrics after deploy…');

    return await fetchMetaStatsMetrics(metaapiCloudAccountId, token, region, {
      includeOpenPositions: true,
    });
  }
}

function logSyncPhase(accountKey, label, startedMs) {
  console.log(`[MetaApi sync][${accountKey}] ${label} ${Date.now() - startedMs}ms`);
}

async function clearAdminBulkSyncProgress() {
  return clearAdminBulkSyncProgressDoc(db, COLLECTIONS, ADMIN_SYNC_PROGRESS_DOC_ID);
}

async function syncMetaApiTradeDocuments(
  account,
  accountForMetaApi,
  token,
  region,
  accountInfo,
  syncRunId,
  nowIso,
  progressCtx = null,
) {
  const accountKey = account.id || account.metaapi_account_id;
  const accountDocId = String(accountKey);
  const phaseStart = Date.now();
  const report = async (phase, message, extra = {}) => {
    if (progressCtx?.report) {
      await progressCtx.report(phase, message, extra);
    } else {
      await reportAccountSyncProgressThrottled(
        db,
        COLLECTIONS,
        accountDocId,
        phase,
        message,
        extra,
        omitUndefinedFirestoreFields,
      );
    }
  };

  const platform =
    account.platform === 'mt4' || account.platform === 'mt5'
      ? account.platform
      : accountInfo.platform === 'mt4' || accountInfo.platform === 'mt5'
        ? accountInfo.platform
        : 'mt5';

  await report('fetch_deals', 'Fetching trade history from MetaApi…');
  const rawDeals = await fetchMetaApiTrades(
    accountForMetaApi,
    token,
    undefined,
    undefined,
    region,
    ({ loaded, pageRows }) => {
      if (pageRows > 0) {
        logSyncPhase(accountKey, `deals paging (no Firestore) loaded=${loaded}`, phaseStart);
      }
    },
  );
  logSyncPhase(accountKey, `fetched deals=${Array.isArray(rawDeals) ? rawDeals.length : 0}`, phaseStart);

  await report('fetch_positions', 'Fetching open positions…');
  const rawPositions = await fetchMetaApiPositions(accountForMetaApi, token, region);

  const { normalizedTrades } = deriveSyncedMetricsPackage(
    Number(accountInfo.balance || 0),
    Array.isArray(rawDeals) ? rawDeals : [],
    platform,
  );

  const normalizedDeals = normalizedTrades.map((trade) => ({
    id: `${accountKey}_${trade.id}`,
    data: {
      user_id: account.user_id,
      account_id: accountKey,
      account_login: account.login || '',
      symbol: trade.symbol || '',
      type: trade.type,
      volume: Number(trade.volume || 0),
      openPrice: Number(trade.openPrice || 0),
      closePrice: Number(trade.closePrice || 0),
      profit: Number(trade.profit || 0),
      openTime: trade.openTime ?? null,
      closeTime: trade.closeTime ?? null,
      swap: Number(trade.swap || 0),
      commission: Number(trade.commission || 0),
      comment: trade.comment ?? null,
      metaapi_account_id: account.metaapi_account_id,
      metaapi_region: region,
      synced_at: nowIso,
      sync_run_id: syncRunId,
      createdAt: FieldValue.serverTimestamp(),
    },
  }));

  const normalizedPositions = (Array.isArray(rawPositions) ? rawPositions : []).map((position) => ({
    id: `${accountKey}_${position.id}`,
    data: {
      user_id: account.user_id,
      account_id: accountKey,
      account_login: account.login || '',
      symbol: position.symbol || '',
      type: position.type,
      volume: Number(position.volume || 0),
      openPrice: Number(position.openPrice || 0),
      currentPrice: Number(position.currentPrice || 0),
      profit: Number(position.profit || 0),
      openTime: position.openTime ?? null,
      swap: Number(position.swap || 0),
      commission: Number(position.commission || 0),
      metaapi_account_id: account.metaapi_account_id,
      metaapi_region: region,
      synced_at: nowIso,
      sync_run_id: syncRunId,
      createdAt: FieldValue.serverTimestamp(),
    },
  }));

  const writeStart = Date.now();
  await report('write_trades', `Saving ${normalizedDeals.length} trades to database…`, {
    tradesCount: normalizedDeals.length,
  });
  await writeDocuments(COLLECTIONS.metaApiTrades, normalizedDeals);
  await report('write_positions', `Saving ${normalizedPositions.length} open positions…`, {
    positionsCount: normalizedPositions.length,
  });
  await writeDocuments(COLLECTIONS.metaApiPositions, normalizedPositions);
  logSyncPhase(
    accountKey,
    `wrote trades=${normalizedDeals.length} positions=${normalizedPositions.length}`,
    writeStart,
  );

  return {
    tradesSynced: normalizedDeals.length,
    positionsSynced: normalizedPositions.length,
  };
}

function shouldDeferTradeSync(requestedBy, options = {}) {
  if (options.deferTradeSync === true) return true;
  if (options.deferTradeSync === false || options.fullSync === true) return false;
  return requestedBy === 'admin_ui' || requestedBy === 'user_ui';
}

/** Account-doc progress phases that bypass Firestore-rate throttling (or are required during bulk Sync All). */
const IMMEDIATE_ACCOUNT_SYNC_PROGRESS_PHASES = new Set(['starting', 'error', 'syncing_trades', 'skipped_trades']);

async function syncMetaApiAccountSnapshot(account, requestedBy = 'scheduled', options = {}) {
  const deferTradeSync = shouldDeferTradeSync(requestedBy, options);
  const tradesMode = resolveTradesMode(requestedBy, options);
  const accountKey = account.id || account.metaapi_account_id;
  const accountDocId = String(accountKey);
  const syncStarted = Date.now();
  const bulk = options.bulkProgress || null;

  const mergedProgressMessage = (message) =>
    bulk && bulk.total > 1
      ? `Account ${bulk.index}/${bulk.total} (#${account.login || accountDocId}): ${message}`
      : message;

  const report = async (phase, message, extra = {}) => {
    const mergedMsg = mergedProgressMessage(message);

    if (bulk) {
      await reportAdminBulkSyncProgressThrottled(db, COLLECTIONS, ADMIN_SYNC_PROGRESS_DOC_ID, {
        active: true,
        mode: 'all',
        index: bulk.index,
        total: bulk.total,
        currentAccountId: accountDocId,
        currentLogin: account.login || '',
        phase,
        message: mergedMsg,
        ...extra,
      });
      if (!IMMEDIATE_ACCOUNT_SYNC_PROGRESS_PHASES.has(phase)) return;
    }

    const progressiveWrite = IMMEDIATE_ACCOUNT_SYNC_PROGRESS_PHASES.has(phase)
      ? flushAccountThrottleNow
      : reportAccountSyncProgressThrottled;

    await progressiveWrite(
      db,
      COLLECTIONS,
      accountDocId,
      phase,
      mergedMsg,
      extra,
      omitUndefinedFirestoreFields,
    );
  };

  const progressCtx = { report };

  const persistTradeSyncErrorOnAccountDoc = async (tradeErrorMessage) => {
    forgetAccountThrottleState(accountDocId);
    await db.collection(COLLECTIONS.accounts).doc(accountDocId).set(
      omitUndefinedFirestoreFields({
        metaapi_sync_status: 'error',
        metaapi_sync_error: `Metrics saved; trade history sync failed: ${tradeErrorMessage}`,
        metaapi_sync_progress: {
          phase: 'error',
          message: tradeErrorMessage,
          updatedAt: new Date().toISOString(),
        },
        updatedAt: FieldValue.serverTimestamp(),
      }),
      { merge: true },
    );
  };

  try {
    await report('starting', 'Starting MetaApi sync…');

    const settings = await getSiteSettings();
    const tokenCandidates = resolveMetaApiTokenCandidates(account, settings);
    if (!account.metaapi_account_id || tokenCandidates.length === 0) {
      throw new Error(`MetaApi credentials missing for account ${account.login || accountKey}.`);
    }

    const metaapiCloudAccountId = assertMetaApiCloudAccountId(account.metaapi_account_id, account.login);
    const accountForMetaApi = { ...account, metaapi_account_id: metaapiCloudAccountId };

    await report('provisioning', 'Fetching MetaApi account details…');
    const { token, data: regionPayload } = await requestMetaApiAccountDetailsWithTokens(
      metaapiCloudAccountId,
      tokenCandidates,
    );
    assertProvisioningReadyForClientApi(regionPayload, metaapiCloudAccountId);
    const region = resolveMetaApiHostedRegion(regionPayload, accountForMetaApi);

    await report('account_info', 'Fetching live balance and equity…');
    const accountInfo = await fetchMetaApiAccountInfo(accountForMetaApi, token, region);
    logSyncPhase(accountKey, 'account info', syncStarted);

    await report('metastats', 'Fetching MetaStats metrics…');
    const metaStatsRaw = await fetchMetaStatsWithProvisioningRecovery(metaapiCloudAccountId, token, region);
    let mappedMetrics;
    try {
      mappedMetrics = mapMetaStatsToAccountMetrics(metaStatsRaw);
    } catch (err) {
      throw new Error(
        `MetaStats metrics mapping failed for ${account.login || metaapiCloudAccountId}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    logSyncPhase(accountKey, 'metastats', syncStarted);

    let metricsActivitySource = 'metastats';
    const platform =
      account.platform === 'mt4' || account.platform === 'mt5'
        ? account.platform
        : accountInfo.platform === 'mt4' || accountInfo.platform === 'mt5'
          ? accountInfo.platform
          : 'mt5';

    if (isMetaStatsActivityEmpty(mappedMetrics)) {
      const terminalBalance =
        mappedMetrics.balance != null && Number.isFinite(mappedMetrics.balance)
          ? mappedMetrics.balance
          : Number(accountInfo.balance || 0);

      await report('metrics_fallback', 'MetaStats reported no activity; checking stored trades…');
      const tradeDocs = await loadFirestoreTradesForAccount(
        account.user_id,
        accountKey,
        metaapiCloudAccountId,
        account.login || '',
      );
      const fromFirestore = deriveMetricsFromFirestoreTradeDocs(tradeDocs, terminalBalance);
      if ((fromFirestore.metrics.total_trades ?? 0) > 0) {
        mergeActivityMetricsInto(mappedMetrics, fromFirestore.metrics);
        metricsActivitySource = 'firestore_trades';
        console.log(
          `[MetaStats][fallback] firestore_trades account=${accountKey} trades=${fromFirestore.metrics.total_trades}`,
        );
      } else {
        await report('metrics_fallback', 'Fetching full deal history from MetaApi…');
        const clientApiUrl = getClientApiUrl(region);
        const rawDeals = await fetchMetaApiHistoryDealsFullRange(
          clientApiUrl,
          metaapiCloudAccountId,
          token,
          ({ loaded }) => {
            if (loaded > 0 && loaded % 500 === 0) {
              logSyncPhase(accountKey, `metrics fallback deals loaded=${loaded}`, syncStarted);
            }
          },
        );
        const { metrics: dealMetrics } = deriveSyncedMetricsPackage(
          terminalBalance,
          Array.isArray(rawDeals) ? rawDeals : [],
          platform,
        );
        if ((dealMetrics.total_trades ?? 0) > 0) {
          mergeActivityMetricsInto(mappedMetrics, dealMetrics);
          metricsActivitySource = 'metaapi_deals';
          console.log(
            `[MetaStats][fallback] metaapi_deals account=${accountKey} trades=${dealMetrics.total_trades}`,
          );
        }
      }
      logSyncPhase(accountKey, `metrics activity source=${metricsActivitySource}`, syncStarted);
    }

    const nowIso = new Date().toISOString();
    const syncRunId = `${accountKey}-${Date.now()}`;

    const headlineBalance =
      mappedMetrics.balance != null && Number.isFinite(mappedMetrics.balance)
        ? mappedMetrics.balance
        : Number(accountInfo.balance || 0);
    const headlineEquity =
      mappedMetrics.equity != null && Number.isFinite(mappedMetrics.equity)
        ? mappedMetrics.equity
        : Number(accountInfo.equity || 0);
    const headlineGain = mappedMetrics.gain != null && Number.isFinite(mappedMetrics.gain) ? mappedMetrics.gain : 0;
    const headlineDd = mappedMetrics.dd != null && Number.isFinite(mappedMetrics.dd) ? mappedMetrics.dd : 0;
    const headlineProfit =
      mappedMetrics.profit != null && Number.isFinite(mappedMetrics.profit) ? mappedMetrics.profit : 0;
    const headlineWin =
      mappedMetrics.win_rate != null && Number.isFinite(mappedMetrics.win_rate) ? mappedMetrics.win_rate : 0;
    const headlineTotalTrades =
      mappedMetrics.total_trades != null && Number.isFinite(mappedMetrics.total_trades)
        ? mappedMetrics.total_trades
        : 0;

    const metaStatsBody = unwrapMetaStatsMetricsBody(metaStatsRaw);
    const metaapiDailyGrowth = normalizeDailyGrowthSeries(metaStatsBody?.dailyGrowth, {
      terminalBalance: headlineBalance,
      terminalEquity: headlineEquity,
    });

    const persistMeta = {
      balance: headlineBalance,
      equity: headlineEquity,
      gain: headlineGain,
      dd: headlineDd,
      profit: headlineProfit,
      win_rate: headlineWin,
      total_trades: headlineTotalTrades,
      metaapi_abs_gain:
        mappedMetrics.metaapi_abs_gain != null && Number.isFinite(mappedMetrics.metaapi_abs_gain)
          ? mappedMetrics.metaapi_abs_gain
          : null,
      metaapi_daily_gain:
        mappedMetrics.metaapi_daily_gain != null && Number.isFinite(mappedMetrics.metaapi_daily_gain)
          ? mappedMetrics.metaapi_daily_gain
          : null,
      metaapi_monthly_gain:
        mappedMetrics.metaapi_monthly_gain != null && Number.isFinite(mappedMetrics.metaapi_monthly_gain)
          ? mappedMetrics.metaapi_monthly_gain
          : null,
      metaapi_highest_balance:
        mappedMetrics.metaapi_highest_balance != null &&
        Number.isFinite(mappedMetrics.metaapi_highest_balance)
          ? mappedMetrics.metaapi_highest_balance
        : null,
      metaapi_highest_balance_date: mappedMetrics.metaapi_highest_balance_date ?? null,
      metaapi_interest:
        mappedMetrics.metaapi_interest != null && Number.isFinite(mappedMetrics.metaapi_interest)
          ? mappedMetrics.metaapi_interest
          : null,
      metaapi_deposits:
        mappedMetrics.metaapi_deposits != null && Number.isFinite(mappedMetrics.metaapi_deposits)
          ? mappedMetrics.metaapi_deposits
          : null,
      metaapi_withdrawals:
        mappedMetrics.metaapi_withdrawals != null &&
        Number.isFinite(mappedMetrics.metaapi_withdrawals)
          ? mappedMetrics.metaapi_withdrawals
          : null,
      metaapi_metrics_synced_at: nowIso,
      metaapi_metrics_activity_source: metricsActivitySource,
      metaapi_daily_growth: metaapiDailyGrowth,
      metaapi_daily_growth_synced_at: nowIso,
    };
    console.log('[MetaStats][persist]', safeJsonSnippet(persistMeta));

    const accountSnapshot = {
      user_id: account.user_id,
      account_id: account.id || account.metaapi_account_id,
      account_login: account.login || '',
      broker_name: account.broker_name || '',
      balance: Number(accountInfo.balance || 0),
      equity: Number(accountInfo.equity || 0),
      margin: Number(accountInfo.margin || 0),
      freeMargin: Number(accountInfo.freeMargin || 0),
      leverage: Number(accountInfo.leverage || 0),
      currency: String(accountInfo.currency || ''),
      server: String(accountInfo.server || ''),
      broker: String(accountInfo.broker || ''),
      raw: accountInfo,
      meta_stats_metrics_raw: slimMetaStatsForStorage(metaStatsRaw),
      meta_stats_metrics_mapped: mappedMetrics,
      metaapi_account_id: account.metaapi_account_id,
      metaapi_region: region,
      synced_at: nowIso,
      sync_run_id: syncRunId,
      createdAt: FieldValue.serverTimestamp(),
    };

    await report('persist_metrics', 'Saving metrics to database…');
    await db.collection(COLLECTIONS.metaApiAccountSnapshots).doc(accountDocId).set(
      omitUndefinedFirestoreFields(accountSnapshot),
      { merge: false },
    );

    const statusAfterMetrics =
      deferTradeSync && tradesMode !== METAAPI_TRADES_METRICS_ONLY ? 'syncing_trades' : 'success';

    await db.collection(COLLECTIONS.accounts).doc(accountDocId).set(
      omitUndefinedFirestoreFields({
        ...persistMeta,
        metaapi_daily_growth: sanitizeDailyGrowthSeriesForFirestore(metaapiDailyGrowth),
        metaapi_region: region,
        last_metaapi_sync_at: nowIso,
        metaapi_sync_status: statusAfterMetrics,
        metaapi_sync_error: null,
        metaapi_snapshot_version: FieldValue.increment(1),
        updatedAt: FieldValue.serverTimestamp(),
      }),
      { merge: true },
    );
    logSyncPhase(accountKey, 'metrics persisted', syncStarted);

    const finishSuccess = async (tradeCounts) => {
      if (bulk) {
        await reportAdminBulkSyncProgressThrottled(db, COLLECTIONS, ADMIN_SYNC_PROGRESS_DOC_ID, {
          active: true,
          mode: 'all',
          index: bulk.index,
          total: bulk.total,
          currentAccountId: accountDocId,
          currentLogin: account.login || '',
          phase: 'complete',
          message: mergedProgressMessage(
            `Saved (${tradeCounts.tradesSynced} trades, ${tradeCounts.positionsSynced} positions).`,
          ),
          tradesSynced: tradeCounts.tradesSynced,
          positionsSynced: tradeCounts.positionsSynced,
        });
      }

      forgetAccountThrottleState(accountDocId);
      await db.collection(COLLECTIONS.accounts).doc(accountDocId).set(
        omitUndefinedFirestoreFields({
          metaapi_sync_status: 'success',
          metaapi_sync_error: null,
          last_metaapi_sync_at: nowIso,
          updatedAt: FieldValue.serverTimestamp(),
          metaapi_sync_progress: null,
        }),
        { merge: true },
      );
      logSyncPhase(accountKey, 'complete', syncStarted);
      return tradeCounts;
    };

    if (tradesMode === METAAPI_TRADES_METRICS_ONLY) {
      await report(
        'skipped_trades',
        'Skipped trade persistence (metrics-only sync mode); headline metrics saved.',
      );
      await finishSuccess({ tradesSynced: 0, positionsSynced: 0 });
      return {
        accountId: accountKey,
        syncRunId,
        tradesSynced: 0,
        positionsSynced: 0,
        tradesMode,
        requestedBy,
        syncedAt: nowIso,
      };
    }

    if (deferTradeSync) {
      await report('syncing_trades', 'Metrics saved. Syncing trade history in background…');
      void (async () => {
        try {
          const tradeCounts = await syncMetaApiTradeDocuments(
            account,
            accountForMetaApi,
            token,
            region,
            accountInfo,
            syncRunId,
            nowIso,
            progressCtx,
          );
          await finishSuccess(tradeCounts);
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          console.error(`[MetaApi sync][${accountKey}] background trades failed:`, message);
          await persistTradeSyncErrorOnAccountDoc(message);
        }
      })();

      return {
        accountId: accountKey,
        syncRunId,
        tradesSynced: 0,
        positionsSynced: 0,
        tradesSync: 'background',
        tradesMode,
        requestedBy,
        syncedAt: nowIso,
      };
    }

    const tradeCounts = await syncMetaApiTradeDocuments(
      account,
      accountForMetaApi,
      token,
      region,
      accountInfo,
      syncRunId,
      nowIso,
      progressCtx,
    );
    await finishSuccess(tradeCounts);
    return {
      accountId: accountKey,
      syncRunId,
      tradesSynced: tradeCounts.tradesSynced,
      positionsSynced: tradeCounts.positionsSynced,
      tradesMode,
      requestedBy,
      syncedAt: nowIso,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await flushAccountThrottleNow(
      db,
      COLLECTIONS,
      accountDocId,
      'error',
      message,
      {},
      omitUndefinedFirestoreFields,
    );
    throw err;
  }
}

async function syncAllMetaApiAccountsInternal(requestedBy = 'scheduled') {
  const accountsSnap = await db.collection(COLLECTIONS.accounts)
    .where('status', '==', 'connected')
    .get();

  const eligible = accountsSnap.docs
    .map((accountDoc) => ({ id: accountDoc.id, ...accountDoc.data() }))
    .filter((account) => account.metaapi_account_id && account.metaapi_token);

  const total = eligible.length;
  await reportAdminBulkSyncProgressThrottled(db, COLLECTIONS, ADMIN_SYNC_PROGRESS_DOC_ID, {
    active: true,
    mode: 'all',
    phase: 'starting',
    message: `Starting sync for ${total} connected account(s)…`,
    index: 0,
    total,
  });

  const results = [];
  let index = 0;
  const bulkSyncAll = requestedBy === 'admin_manual';
  for (const account of eligible) {
    index += 1;
    const accountDocId = account.id;

    try {
      const syncOptions =
        requestedBy === 'admin_manual'
          ? { fullSync: true, bulkSyncAll, bulkProgress: { index, total } }
          : { bulkProgress: { index, total } };

      const result = await syncMetaApiAccountSnapshot(account, requestedBy, syncOptions);
      results.push({ ok: true, ...result });
    } catch (error) {
      forgetAccountThrottleState(accountDocId);
      const msg = error instanceof Error ? error.message : String(error);
      await db.collection(COLLECTIONS.accounts).doc(accountDocId).set(
        omitUndefinedFirestoreFields({
          metaapi_sync_status: 'error',
          metaapi_sync_error: msg,
          metaapi_sync_progress: {
            phase: 'error',
            message: msg,
            updatedAt: new Date().toISOString(),
          },
          updatedAt: FieldValue.serverTimestamp(),
        }),
        { merge: true },
      );
      results.push({ ok: false, accountId: accountDocId, error: msg });
    }
  }

  await reportAdminBulkSyncProgressThrottled(db, COLLECTIONS, ADMIN_SYNC_PROGRESS_DOC_ID, {
    active: false,
    mode: 'all',
    phase: 'complete',
    message: `Finished syncing ${total} account(s).`,
    index: total,
    total,
  });

  await db.collection(COLLECTIONS.metaApiSyncRuns).add({
    requestedBy,
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    totalAccounts: total,
    successCount: results.filter((item) => item.ok).length,
    failureCount: results.filter((item) => !item.ok).length,
    results,
    createdAt: FieldValue.serverTimestamp(),
  });

  return { ok: true, totalAccounts: total, results };
}

async function getMetaApiAccountInfoWithRetry(account, maxAttempts = 3) {
  let attempt = 0;
  while (attempt < maxAttempts) {
    attempt += 1;
    try {
      return await getMetaApiAccountInfo(account);
    } catch (error) {
      if (!isTransientMetaApiError(error) || attempt >= maxAttempts) {
        throw error;
      }
      await delay(attempt * 750);
    }
  }

  throw new Error('MetaApi request failed unexpectedly.');
}

function resolveDrawdownAtCapture(metaApiInfo) {
  const candidates = [
    metaApiInfo?.relativeDrawdown,
    metaApiInfo?.drawdown,
    metaApiInfo?.maxRelativeDrawdown,
    metaApiInfo?.maxDrawdown,
  ];

  for (const item of candidates) {
    const value = Number(item);
    if (Number.isFinite(value)) {
      return value;
    }
  }

  return null;
}

/** MetaStats-synced drawdown on tradingAccounts (same source as Admin Account Metrics). */
function resolveDrawdownFromAccountDoc(account) {
  const dd = Number(account?.dd);
  if (Number.isFinite(dd)) return dd;
  return null;
}

function resolveDrawdownForPftCapture(metaApiInfo, account) {
  const fromRpc = resolveDrawdownAtCapture(metaApiInfo);
  if (fromRpc != null) return { drawdown: fromRpc, drawdownSource: 'metaapi_account_information' };
  const fromDoc = resolveDrawdownFromAccountDoc(account);
  if (fromDoc != null) return { drawdown: fromDoc, drawdownSource: 'metastats_account_doc' };
  return { drawdown: null, drawdownSource: null };
}

function isParticipantRankEligible(status) {
  return status !== 'disqualified' && status !== 'invalid';
}

async function getParticipantsByIds(participantIds) {
  const filteredIds = [...new Set(participantIds.filter(Boolean))];
  if (filteredIds.length === 0) return new Map();

  const result = new Map();
  const chunks = chunkArray(filteredIds, 300);
  for (const chunk of chunks) {
    const refs = chunk.map((id) => db.collection(COLLECTIONS.participants).doc(String(id)));
    const docs = await db.getAll(...refs);
    docs.forEach((docSnap) => {
      if (!docSnap.exists) return;
      result.set(docSnap.id, docSnap.data());
    });
  }

  return result;
}

function parseCaptureLockTime(value) {
  if (!value) return null;
  if (typeof value === 'string') {
    const timestamp = new Date(value).getTime();
    return Number.isNaN(timestamp) ? null : timestamp;
  }
  if (typeof value.toDate === 'function') {
    return value.toDate().getTime();
  }
  return null;
}

function sortSnapshotsForLeaderboard(items) {
  return [...items].sort((left, right) => {
    if ((right.gainPercent || 0) !== (left.gainPercent || 0)) {
      return (right.gainPercent || 0) - (left.gainPercent || 0);
    }

    const captureDiff = new Date(left.captureTimestamp || 0).getTime() - new Date(right.captureTimestamp || 0).getTime();
    if (captureDiff !== 0) return captureDiff;

    const leftDrawdown = Number(left.drawdownAtCapture);
    const rightDrawdown = Number(right.drawdownAtCapture);
    const leftDrawdownValid = Number.isFinite(leftDrawdown);
    const rightDrawdownValid = Number.isFinite(rightDrawdown);
    if (leftDrawdownValid && rightDrawdownValid && leftDrawdown !== rightDrawdown) {
      return leftDrawdown - rightDrawdown;
    }
    if (leftDrawdownValid !== rightDrawdownValid) {
      return leftDrawdownValid ? -1 : 1;
    }

    const joinDiff = new Date(left.joinedAt || 0).getTime() - new Date(right.joinedAt || 0).getTime();
    if (joinDiff !== 0) return joinDiff;

    return String(left.accountId || '').localeCompare(String(right.accountId || ''));
  });
}

async function ensureDefaultProgram(adminId) {
  const ref = db.collection(COLLECTIONS.programs).doc('default');
  const snap = await ref.get();
  if (snap.exists) {
    return { ok: true, existed: true, id: ref.id };
  }

  const now = new Date();
  const end = new Date(now);
  end.setMonth(end.getMonth() + 7);
  await ref.set({
    name: 'PFT Contest Program',
    programStartAt: now.toISOString(),
    programEndAt: end.toISOString(),
    batchFrequencyDays: 14,
    batchDurationDays: 14,
    leaderboardSize: DEFAULT_TOP_200_SIZE,
    status: 'active',
    currentBatchNumber: 1,
    createdBy: adminId,
    createdAt: FieldValue.serverTimestamp(),
    updatedAt: FieldValue.serverTimestamp(),
  }, { merge: true });

  return { ok: true, existed: false, id: ref.id };
}

async function listBatchParticipants(batchId) {
  const snap = await db.collection(COLLECTIONS.participants).where('batchId', '==', batchId).get();
  return snap.docs
    .map((item) => ({ id: item.id, ...item.data() }))
    .sort((left, right) => new Date(left.joinedAt || 0).getTime() - new Date(right.joinedAt || 0).getTime());
}

async function listBatchSnapshots(batchId) {
  const snap = await db.collection(COLLECTIONS.snapshots).where('batchId', '==', batchId).get();
  return snap.docs
    .map((item) => ({ id: item.id, ...item.data() }))
    .sort((left, right) => new Date(right.captureTimestamp || 0).getTime() - new Date(left.captureTimestamp || 0).getTime());
}

async function listPftJobs(batchId, maxItems = 50) {
  const normalizedLimit = Math.max(1, Math.min(Number(maxItems) || 50, 200));
  const snap = batchId
    ? await db.collection(COLLECTIONS.jobs).where('batchId', '==', String(batchId)).get()
    : await db.collection(COLLECTIONS.jobs).orderBy('createdAt', 'desc').limit(normalizedLimit).get();

  const jobs = snap.docs
    .map((item) => ({ id: item.id, ...item.data() }))
    .sort((left, right) => new Date(right.startedAt || right.finishedAt || 0).getTime() - new Date(left.startedAt || left.finishedAt || 0).getTime());

  return batchId ? jobs.slice(0, normalizedLimit) : jobs;
}

async function listPftEnrollmentOptionsFast() {
  const accountSnap = await db.collection(COLLECTIONS.accounts).where('status', '==', 'connected').get();
  const accounts = accountSnap.docs
    .map((item) => ({ id: item.id, ...item.data() }))
    .sort((left, right) => new Date(right.connected_at || 0).getTime() - new Date(left.connected_at || 0).getTime());

  const userIds = [...new Set(accounts.map((account) => String(account.user_id || '')).filter(Boolean))];
  const userMap = new Map();
  const userIdChunks = chunkArray(userIds, 300);
  for (const userIdChunk of userIdChunks) {
    const refs = userIdChunk.map((id) => db.collection(COLLECTIONS.users).doc(id));
    const docs = await db.getAll(...refs);
    docs.forEach((docSnap) => {
      if (!docSnap.exists) return;
      userMap.set(docSnap.id, docSnap.data() || {});
    });
  }

  return accounts.map((account) => {
    const userData = userMap.get(String(account.user_id || '')) || {};
    const username = String(userData.name || userData.displayName || userData.email || account.user_id || 'Unknown');
    return {
      accountId: String(account.id || ''),
      label: `${username} • ${account.broker_name} • ${account.login}`,
      userId: String(account.user_id || ''),
      username,
      platform: resolveTradingAccountPlatform(account),
      balance: Number(account.balance || 0),
      equity: Number(account.equity || 0),
    };
  });
}

async function getActiveBatchIds() {
  const batchSnap = await db.collection(COLLECTIONS.batches)
    .where('status', 'in', ['scheduled', 'active', 'capturing'])
    .get();
  return new Set(batchSnap.docs.map((item) => item.id));
}

function mapBatchStatusToContestStatus(batchStatus) {
  switch (String(batchStatus || '')) {
    case 'scheduled':
      return 'published';
    case 'active':
      return 'ongoing';
    case 'capturing':
    case 'completed':
    case 'archived':
      return 'completed';
    default:
      return 'published';
  }
}

async function createContestForPftBatch(batchId, batchData, createdBy) {
  const batchStatus = String(batchData.status || 'scheduled');
  const contestStatus = mapBatchStatusToContestStatus(batchStatus);
  const contestPayload = {
    broker_id: 'public',
    broker_name: 'RankEdges PFT',
    creator_id: createdBy || batchData.createdBy || 'system',
    creator_type: 'trader',
    creator_name: 'RankEdges Admin',
    name: `PFT Batch ${batchData.batchNumber}`,
    type: 'pft',
    start_at: batchData.startAt,
    end_at: batchData.endAt,
    prize_pool: 0,
    rules: 'Prop Firm Tournament — admin-enrolled participants only.',
    status: contestStatus,
    scoring_mode: 'gain',
    dd_cap: 0,
    participants: Number(batchData.participantCount || 0),
    join_method: 'manual_approval',
    enrollment_mode: 'admin_only',
    pft_batch_id: batchId,
    pft_batch_number: batchData.batchNumber,
    start_mode: 'scheduled',
    availability: 'public',
    access_type: 'open',
    createdAt: FieldValue.serverTimestamp(),
    updatedAt: FieldValue.serverTimestamp(),
  };

  if (batchStatus === 'active') {
    contestPayload.started_at = batchData.startAt || new Date().toISOString();
  }

  if (['capturing', 'completed', 'archived'].includes(batchStatus)) {
    contestPayload.rankings_locked = true;
    contestPayload.rankings_locked_at = batchData.completedAt || batchData.captureTimestamp || new Date().toISOString();
    contestPayload.completed_at = batchData.completedAt || batchData.endAt;
  }

  const contestRef = await db.collection(COLLECTIONS.contests).add(contestPayload);
  return contestRef.id;
}

async function ensureBatchHasContest(batchId, batchData, createdBy) {
  let contestId = batchData.contestId;
  if (!contestId) {
    contestId = await createContestForPftBatch(batchId, batchData, createdBy);
    await db.collection(COLLECTIONS.batches).doc(batchId).set({
      contestId,
      updatedAt: FieldValue.serverTimestamp(),
    }, { merge: true });
  }

  await syncPftBatchContestLeaderboard(batchId, contestId);
  return contestId;
}

async function syncContestStatusFromBatch(batchId, batchData) {
  const contestId = batchData.contestId;
  if (!contestId) return null;

  const batchStatus = String(batchData.status || 'scheduled');
  const updates = {
    status: mapBatchStatusToContestStatus(batchStatus),
    updatedAt: FieldValue.serverTimestamp(),
  };

  if (batchStatus === 'active') {
    updates.started_at = batchData.startAt || new Date().toISOString();
  }

  if (['capturing', 'completed', 'archived'].includes(batchStatus)) {
    updates.rankings_locked = true;
    updates.rankings_locked_at = batchData.completedAt || batchData.captureTimestamp || new Date().toISOString();
    updates.completed_at = batchData.completedAt || batchData.endAt;
  }

  await db.collection(COLLECTIONS.contests).doc(contestId).set(updates, { merge: true });
  return contestId;
}

const PFT_ENROLLABLE_STATUSES = new Set(['active', 'completed', 'disqualified']);

function countPftBatchEnrollments(participants) {
  return participants.filter((participant) => PFT_ENROLLABLE_STATUSES.has(String(participant.status || ''))).length;
}

async function updateContestRankingsServer(contestId, options = {}) {
  const { force = false } = options;
  const contestSnap = await db.collection(COLLECTIONS.contests).doc(contestId).get();
  const contest = contestSnap.exists ? { id: contestSnap.id, ...contestSnap.data() } : null;
  if (!contest) return;
  if (contest.rankings_locked && !force) return;

  const rawSnap = await db.collection(COLLECTIONS.leaderboard).where('contest_id', '==', contestId).get();
  const rawEntries = rawSnap.docs.map((item) => ({ id: item.id, ...item.data() }));

  const dedupeKey = contest.type === 'pft' ? 'account_id' : 'user_id';
  const byKey = new Map();
  for (const entry of rawEntries) {
    const key = String(entry[dedupeKey] || entry.user_id || entry.account_id || entry.id);
    const existing = byKey.get(key) || [];
    existing.push(entry);
    byKey.set(key, existing);
  }

  const deduped = [];
  const dedupeBatch = db.batch();
  for (const [, entries] of byKey) {
    if (entries.length === 1) {
      deduped.push(entries[0]);
      continue;
    }
    entries.sort((left, right) => (Number(right.score) || 0) - (Number(left.score) || 0));
    deduped.push(entries[0]);
    for (let index = 1; index < entries.length; index += 1) {
      dedupeBatch.delete(db.collection(COLLECTIONS.leaderboard).doc(entries[index].id));
    }
  }
  await dedupeBatch.commit();

  let allRanked;
  if (contest.type === 'pft') {
    const batchSnap = contest.pft_batch_id
      ? await db.collection(COLLECTIONS.batches).doc(String(contest.pft_batch_id)).get()
      : null;
    const batchData = batchSnap?.exists ? batchSnap.data() : null;
    allRanked = rankPftLeaderboardEntries(deduped, {
      rankingsLocked: Boolean(contest.rankings_locked),
      captureTimestamp: batchData?.captureTimestamp || contest.completed_at,
    });
  } else {
    const active = deduped.filter((entry) => entry.participant_status !== 'disqualified');
    const disqualified = deduped.filter((entry) => entry.participant_status === 'disqualified');
    const sorted = [...active].sort((left, right) => {
      if ((Number(right.score) || 0) !== (Number(left.score) || 0)) {
        return (Number(right.score) || 0) - (Number(left.score) || 0);
      }
      if ((Number(left.dd) || 0) !== (Number(right.dd) || 0)) {
        return (Number(left.dd) || 0) - (Number(right.dd) || 0);
      }
      const leftTime = left.createdAt?.toMillis?.() ?? 0;
      const rightTime = right.createdAt?.toMillis?.() ?? 0;
      return leftTime - rightTime;
    });
    allRanked = [...sorted, ...disqualified].map((entry, index) => ({ ...entry, rank: index + 1 }));
  }

  const rankBatch = db.batch();
  allRanked.forEach((entry) => {
    rankBatch.set(db.collection(COLLECTIONS.leaderboard).doc(entry.id), {
      rank: entry.rank,
      updatedAt: FieldValue.serverTimestamp(),
    }, { merge: true });
  });
  await rankBatch.commit();
}

async function loadPftBatchForParticipant(participant) {
  if (!participant?.batchId) return null;
  const batchSnap = await db.collection(COLLECTIONS.batches).doc(String(participant.batchId)).get();
  if (!batchSnap.exists) return null;
  return { id: batchSnap.id, ...batchSnap.data() };
}

async function enrollParticipantInPftContest(contestId, participant, account, username, userData) {
  const accountId = String(participant.accountId || account.id || '');
  if (!accountId) return { created: false };

  const [contestSnap, batch, existingLeaderboard, existingParticipation] = await Promise.all([
    db.collection(COLLECTIONS.contests).doc(contestId).get(),
    loadPftBatchForParticipant(participant),
    db.collection(COLLECTIONS.leaderboard)
      .where('contest_id', '==', contestId)
      .where('account_id', '==', accountId)
      .limit(1)
      .get(),
    db.collection(COLLECTIONS.contestParticipations)
      .where('contest_id', '==', contestId)
      .where('account_id', '==', accountId)
      .limit(1)
      .get(),
  ]);

  const contest = contestSnap.exists ? contestSnap.data() : null;
  const rankingsLocked = Boolean(contest?.rankings_locked);
  const participantStatus = mapPftParticipantStatusToContest(participant.status);
  const nowIso = participant.joinedAt || new Date().toISOString();
  const country = String(userData?.country || '');
  const startingBalance = Number(participant.startingBalance || account.balance || 0);
  const startingEquity = Number(participant.startingEquity || account.equity || startingBalance);

  const pftFields = buildPftLeaderboardFields({
    participant,
    account,
    snapshot: null,
    batch,
    existingEntry: existingLeaderboard.empty ? null : existingLeaderboard.docs[0].data(),
    rankingsLocked,
    maskAccountRef: maskAccountReference,
    resolvePlatform: resolveTradingAccountPlatform,
  });

  if (!existingLeaderboard.empty) {
    const entryRef = existingLeaderboard.docs[0].ref;
    await entryRef.set(
      pftLeaderboardPayload(pftFields, {
        trader_name: username,
        updatedAt: FieldValue.serverTimestamp(),
      }),
      { merge: true },
    );

    if (!existingParticipation.empty) {
      const participationUpdates = {
        participant_status: participantStatus,
        trader_name: username,
        current_balance: pftFields.balance,
        peak_equity: pftFields.peak_equity,
        lowest_equity: pftFields.lowest_equity,
      };
      if (participantStatus === 'disqualified') {
        participationUpdates.disqualified_at = participant.disqualifiedAt || new Date().toISOString();
        participationUpdates.disqualified_reason = participant.disqualifiedReason || 'Disqualified';
      }
      await existingParticipation.docs[0].ref.set(
        omitUndefinedFirestoreFields(participationUpdates),
        { merge: true },
      );
    }

    return { created: false, updated: true };
  }

  if (existingParticipation.empty) {
    await db.collection(COLLECTIONS.contestParticipations).add(
      omitUndefinedFirestoreFields({
        contest_id: contestId,
        user_id: participant.userId,
        account_id: accountId,
        trader_name: username,
        trader_avatar: userData?.avatar || userData?.photoURL || '',
        country,
        joined_at: nowIso,
        participant_status: participantStatus,
        starting_balance: startingBalance,
        current_balance: pftFields.balance,
        peak_equity: startingEquity,
        lowest_equity: startingEquity,
        createdAt: FieldValue.serverTimestamp(),
      }),
    );
  }

  await db.collection(COLLECTIONS.leaderboard).add(
    pftLeaderboardPayload(pftFields, {
      contest_id: contestId,
      scope: 'contest',
      account_id: accountId,
      user_id: participant.userId,
      trader_name: username,
      trader_avatar: userData?.avatar || userData?.photoURL || '',
      country,
      rank: 1,
      createdAt: FieldValue.serverTimestamp(),
    }),
  );

  return { created: true };
}

async function syncPftLeaderboardFields(batchId, contestId) {
  if (!batchId || !contestId) return { updated: 0 };

  const [participants, snapshots, batchSnap, contestSnap, lbSnap] = await Promise.all([
    listBatchParticipants(batchId),
    listBatchSnapshots(batchId),
    db.collection(COLLECTIONS.batches).doc(batchId).get(),
    db.collection(COLLECTIONS.contests).doc(contestId).get(),
    db.collection(COLLECTIONS.leaderboard).where('contest_id', '==', contestId).get(),
  ]);

  const batch = batchSnap.exists ? { id: batchSnap.id, ...batchSnap.data() } : { id: batchId };
  const contest = contestSnap.exists ? contestSnap.data() : null;
  const rankingsLocked = Boolean(contest?.rankings_locked);
  const officialSnapshots = snapshots.filter((item) => item.isOfficial !== false);
  const snapshotByAccount = new Map(
    officialSnapshots.map((item) => [String(item.accountId), item]),
  );
  const participantByAccount = new Map(
    participants.map((item) => [String(item.accountId), item]),
  );

  const accountIds = [...new Set([
    ...participants.map((item) => String(item.accountId || '')),
    ...lbSnap.docs.map((item) => String(item.data().account_id || '')),
  ].filter(Boolean))];

  const accountMap = new Map();
  for (const accountIdChunk of chunkArray(accountIds, 300)) {
    const refs = accountIdChunk.map((accountId) => db.collection(COLLECTIONS.accounts).doc(accountId));
    const docs = await db.getAll(...refs);
    docs.forEach((docSnap) => {
      if (!docSnap.exists) return;
      accountMap.set(docSnap.id, { id: docSnap.id, ...docSnap.data() });
    });
  }

  const writeBatch = db.batch();
  let updated = 0;

  lbSnap.docs.forEach((docSnap) => {
    const entry = docSnap.data();
    const accountId = String(entry.account_id || '');
    const participant = participantByAccount.get(accountId);
    if (!participant) return;

    const account = accountMap.get(accountId);
    if (!account) return;

    const snapshot = snapshotByAccount.get(accountId);
    const fields = buildPftLeaderboardFields({
      participant,
      account,
      snapshot,
      batch,
      existingEntry: entry,
      rankingsLocked,
      maskAccountRef: maskAccountReference,
      resolvePlatform: resolveTradingAccountPlatform,
    });

    writeBatch.set(
      docSnap.ref,
      pftLeaderboardPayload(fields, {
        trader_name: entry.trader_name || participant.username,
        updatedAt: FieldValue.serverTimestamp(),
      }),
      { merge: true },
    );
    updated += 1;
  });

  if (updated > 0) {
    await writeBatch.commit();
  }

  return { updated };
}

/** @deprecated Use syncPftLeaderboardFields */
async function backfillPftLeaderboardMeta(batchId, contestId) {
  return syncPftLeaderboardFields(batchId, contestId);
}

async function syncPftLiveLeaderboardMetrics(batchId, contestId) {
  if (!batchId || !contestId) {
    return { metricsUpdated: 0 };
  }

  const [batchSnap, contestSnap] = await Promise.all([
    db.collection(COLLECTIONS.batches).doc(batchId).get(),
    db.collection(COLLECTIONS.contests).doc(contestId).get(),
  ]);

  if (!batchSnap.exists || !contestSnap.exists) {
    return { metricsUpdated: 0 };
  }

  const batch = { id: batchSnap.id, ...batchSnap.data() };
  const contest = contestSnap.data();
  if (contest.rankings_locked) {
    return { metricsUpdated: 0, skipped: true, reason: 'rankings_locked' };
  }

  const batchStatus = String(batch.status || '');
  if (!['active', 'scheduled'].includes(batchStatus)) {
    return { metricsUpdated: 0, skipped: true, reason: 'batch_not_live' };
  }

  const fieldResult = await syncPftLeaderboardFields(batchId, contestId);
  await updateContestRankingsServer(contestId);

  return { metricsUpdated: fieldResult.updated, skipped: false };
}

async function refreshActivePftLiveLeaderboards() {
  const batchSnap = await db.collection(COLLECTIONS.batches).where('status', '==', 'active').get();
  const results = [];

  for (const batchDoc of batchSnap.docs) {
    const batchData = batchDoc.data();
    if (!batchData.contestId) continue;
    try {
      const result = await syncPftLiveLeaderboardMetrics(batchDoc.id, batchData.contestId);
      results.push({ batchId: batchDoc.id, contestId: batchData.contestId, ...result });
    } catch (error) {
      results.push({
        batchId: batchDoc.id,
        contestId: batchData.contestId,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return { ok: true, batches: results.length, results };
}

async function syncPftBatchContestLeaderboard(batchId, contestId) {
  if (!batchId || !contestId) {
    return { enrolled: 0, metaUpdated: 0, participants: 0, metricsUpdated: 0 };
  }

  const [participants, batchSnap, contestSnap] = await Promise.all([
    listBatchParticipants(batchId),
    db.collection(COLLECTIONS.batches).doc(batchId).get(),
    db.collection(COLLECTIONS.contests).doc(contestId).get(),
  ]);

  const batchData = batchSnap.exists ? { id: batchSnap.id, ...batchSnap.data() } : { id: batchId };
  const contest = contestSnap.exists ? contestSnap.data() : null;
  const batchStatus = String(batchData.status || '');
  let enrolled = 0;

  for (const participant of participants) {
    if (!PFT_ENROLLABLE_STATUSES.has(String(participant.status || ''))) continue;

    const accountSnap = await db.collection(COLLECTIONS.accounts).doc(String(participant.accountId)).get();
    if (!accountSnap.exists) continue;

    const account = { id: accountSnap.id, ...accountSnap.data() };
    const resolvedPlatform = resolveTradingAccountPlatform(account, participant);
    if (
      participant.id
      && isKnownTradingPlatform(resolvedPlatform)
      && shouldReplaceTradingPlatform(participant.platform)
    ) {
      await db.collection(COLLECTIONS.participants).doc(participant.id).set({
        platform: resolvedPlatform,
        updatedAt: FieldValue.serverTimestamp(),
      }, { merge: true });
      participant.platform = resolvedPlatform;
    }

    const userSnap = await db.collection(COLLECTIONS.users).doc(String(participant.userId)).get();
    const userData = userSnap.exists ? userSnap.data() : {};
    const username = String(
      participant.username
      || userData?.name
      || userData?.displayName
      || userData?.email
      || participant.userId,
    );

    const result = await enrollParticipantInPftContest(
      contestId,
      {
        ...participant,
        joinedAt: participant.joinedAt || participant.startTimestamp,
      },
      account,
      username,
      userData,
    );
    if (result.created) enrolled += 1;
  }

  let metricsUpdated = 0;
  let metaUpdated = 0;
  if (['completed', 'capturing', 'archived'].includes(batchStatus)) {
    const fieldResult = await syncPftLeaderboardFields(batchId, contestId);
    metaUpdated = fieldResult.updated;
    await finalizeContestFromSnapshots(batchId, { ...batchData, contestId }, 'sync');
    await updateContestRankingsServer(contestId, { force: true });
    metricsUpdated = metaUpdated;
  } else if (batchStatus === 'active') {
    const liveResult = await syncPftLiveLeaderboardMetrics(batchId, contestId);
    metricsUpdated = liveResult.metricsUpdated || 0;
    metaUpdated = metricsUpdated;
  } else {
    const fieldResult = await syncPftLeaderboardFields(batchId, contestId);
    metricsUpdated = fieldResult.updated;
    metaUpdated = metricsUpdated;
    await updateContestRankingsServer(contestId);
  }

  const enrolledCount = countPftBatchEnrollments(participants);
  await db.collection(COLLECTIONS.contests).doc(contestId).set({
    participants: enrolledCount,
    updatedAt: FieldValue.serverTimestamp(),
  }, { merge: true });
  await db.collection(COLLECTIONS.batches).doc(batchId).set({
    participantCount: enrolledCount,
    updatedAt: FieldValue.serverTimestamp(),
  }, { merge: true });

  if (!['completed', 'capturing', 'archived'].includes(batchStatus) && batchStatus !== 'active') {
    await updateContestRankingsServer(contestId);
  }

  const leaderboardSnap = await db.collection(COLLECTIONS.leaderboard)
    .where('contest_id', '==', contestId)
    .get();

  return {
    enrolled,
    metaUpdated,
    metricsUpdated,
    participants: enrolledCount,
    performers: leaderboardSnap.size,
  };
}

async function recomputeAllPftContestRankings(adminId) {
  const batchSnap = await db.collection(COLLECTIONS.batches).get();
  const results = [];

  for (const batchDoc of batchSnap.docs) {
    const batchData = batchDoc.data();
    if (!batchData.contestId) {
      results.push({ batchId: batchDoc.id, skipped: true, reason: 'no_contest' });
      continue;
    }

    try {
      const sync = await syncPftBatchContestLeaderboard(batchDoc.id, batchData.contestId);
      results.push({
        batchId: batchDoc.id,
        contestId: batchData.contestId,
        skipped: false,
        ...sync,
      });
    } catch (error) {
      results.push({
        batchId: batchDoc.id,
        contestId: batchData.contestId,
        skipped: false,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return {
    ok: true,
    recomputed: results.filter((item) => !item.skipped && !item.error).length,
    results,
    requestedBy: adminId,
  };
}

async function finalizeContestFromSnapshots(batchId, batchData, adminId) {
  const contestId = batchData.contestId;
  if (!contestId) return;

  const [snapshots, participants] = await Promise.all([
    listBatchSnapshots(batchId),
    listBatchParticipants(batchId),
  ]);
  const batchRecord = { id: batchId, ...batchData };
  const participantByAccount = new Map(
    participants.map((item) => [String(item.accountId), item]),
  );
  const officialSnapshots = snapshots.filter((item) => item.isOfficial !== false);

  const accountIds = [...new Set(officialSnapshots.map((item) => String(item.accountId || '')).filter(Boolean))];
  const accountMap = new Map();
  for (const accountIdChunk of chunkArray(accountIds, 300)) {
    const refs = accountIdChunk.map((accountId) => db.collection(COLLECTIONS.accounts).doc(accountId));
    const docs = await db.getAll(...refs);
    docs.forEach((docSnap) => {
      if (!docSnap.exists) return;
      accountMap.set(docSnap.id, { id: docSnap.id, ...docSnap.data() });
    });
  }

  const updateBatch = db.batch();

  for (const snapshot of officialSnapshots) {
    if (!['completed', 'disqualified'].includes(String(snapshot.status || ''))) continue;

    const accountId = String(snapshot.accountId || '');
    const participant = participantByAccount.get(accountId);
    const account = accountMap.get(accountId);
    if (!participant) continue;

    const lbSnap = await db.collection(COLLECTIONS.leaderboard)
      .where('contest_id', '==', contestId)
      .where('account_id', '==', accountId)
      .limit(1)
      .get();
    if (lbSnap.empty) continue;

    const ref = lbSnap.docs[0].ref;
    const entryData = lbSnap.docs[0].data();
    const fields = buildPftLeaderboardFields({
      participant: {
        ...participant,
        status: snapshot.status === 'disqualified' ? 'disqualified' : participant.status,
      },
      account: account || { id: accountId },
      snapshot,
      batch: batchRecord,
      existingEntry: entryData,
      rankingsLocked: true,
      maskAccountRef: maskAccountReference,
      resolvePlatform: resolveTradingAccountPlatform,
    });

    updateBatch.set(
      ref,
      pftLeaderboardPayload(fields, { updatedAt: FieldValue.serverTimestamp() }),
      { merge: true },
    );
  }

  await updateBatch.commit();
  await updateContestRankingsServer(contestId, { force: true });

  const leaderboardSnap = await db.collection(COLLECTIONS.leaderboard)
    .where('contest_id', '==', contestId)
    .get();
  const sorted = leaderboardSnap.docs
    .map((item) => ({ id: item.id, ...item.data() }))
    .filter((entry) => entry.participant_status !== 'disqualified')
    .sort((left, right) => (Number(left.rank) || 999) - (Number(right.rank) || 999));
  const winnerUserIds = sorted.filter((entry) => Number(entry.rank) <= 3).map((entry) => entry.user_id);

  await db.collection(COLLECTIONS.contests).doc(contestId).set({
    status: 'completed',
    completed_at: batchData.completedAt || new Date().toISOString(),
    completed_by: adminId || 'system',
    rankings_locked: true,
    rankings_locked_at: new Date().toISOString(),
    rankings_locked_by: adminId || 'system',
    winner_user_ids: winnerUserIds,
    updatedAt: FieldValue.serverTimestamp(),
  }, { merge: true });

  const participationsSnap = await db.collection(COLLECTIONS.contestParticipations)
    .where('contest_id', '==', contestId)
    .get();
  const participationBatch = db.batch();
  participationsSnap.docs.forEach((item) => {
    const data = item.data();
    if (data.participant_status !== 'disqualified') {
      participationBatch.set(item.ref, { participant_status: 'completed' }, { merge: true });
    }
  });
  await participationBatch.commit();
}

async function disqualifyParticipantInContest(contestId, participant) {
  if (!contestId) return;

  const lbSnap = await db.collection(COLLECTIONS.leaderboard)
    .where('contest_id', '==', contestId)
    .where('account_id', '==', String(participant.accountId))
    .limit(1)
    .get();
  if (!lbSnap.empty) {
    await lbSnap.docs[0].ref.set({
      participant_status: 'disqualified',
      updatedAt: FieldValue.serverTimestamp(),
    }, { merge: true });
  }

  const participationSnap = await db.collection(COLLECTIONS.contestParticipations)
    .where('contest_id', '==', contestId)
    .where('account_id', '==', String(participant.accountId))
    .limit(1)
    .get();
  if (!participationSnap.empty) {
    await participationSnap.docs[0].ref.set({
      participant_status: 'disqualified',
      disqualified_at: new Date().toISOString(),
      disqualified_reason: participant.disqualifiedReason || 'Manual admin disqualification',
    }, { merge: true });
  }

  await updateContestRankingsServer(contestId);
}

async function migratePftBatchToContest(batchDoc, adminId) {
  const batchId = batchDoc.id;
  const batchData = { id: batchId, ...batchDoc.data() };
  const contestId = await ensureBatchHasContest(batchId, batchData, adminId || batchData.createdBy);

  const participants = await listBatchParticipants(batchId);
  for (const participant of participants) {
    if (!['active', 'completed'].includes(String(participant.status || ''))) continue;

    const accountSnap = await db.collection(COLLECTIONS.accounts).doc(String(participant.accountId)).get();
    if (!accountSnap.exists) continue;
    const account = { id: accountSnap.id, ...accountSnap.data() };
    const userSnap = await db.collection(COLLECTIONS.users).doc(String(participant.userId)).get();
    const userData = userSnap.exists ? userSnap.data() : {};
    const username = String(
      participant.username
      || userData?.name
      || userData?.displayName
      || userData?.email
      || participant.userId,
    );

    await enrollParticipantInPftContest(
      contestId,
      {
        ...participant,
        joinedAt: participant.joinedAt || participant.startTimestamp,
      },
      account,
      username,
      userData,
    );
  }

  await syncPftBatchContestLeaderboard(batchId, contestId);

  if (['completed', 'capturing', 'archived'].includes(String(batchData.status || ''))) {
    await finalizeContestFromSnapshots(batchId, { ...batchData, contestId }, adminId);
  } else {
    await syncContestStatusFromBatch(batchId, { ...batchData, contestId });
  }

  return { batchId, contestId, participantCount: participants.length };
}

async function buildTop200() {
  // Deprecated: PFT rankings live on per-batch contest leaderboards.
  return { ok: true, total: 0, deprecated: true };
}

async function markBatchSnapshotsUnofficial(batchId) {
  const snap = await db.collection(COLLECTIONS.snapshots)
    .where('batchId', '==', batchId)
    .where('isOfficial', '==', true)
    .get();

  if (snap.empty) return;
  const batchWriter = db.batch();
  snap.docs.forEach((item) => {
    batchWriter.update(item.ref, {
      isOfficial: false,
      updatedAt: FieldValue.serverTimestamp(),
    });
  });
  await batchWriter.commit();
}

async function captureBatch(batchId, requestedBy, reprocess = false) {
  const batchRef = db.collection(COLLECTIONS.batches).doc(batchId);
  const batchSnap = await batchRef.get();
  if (!batchSnap.exists) {
    throw new Error('PFT batch not found.');
  }

  const batchData = { id: batchSnap.id, ...batchSnap.data() };
  const lockTimeMs = parseCaptureLockTime(batchData.captureStartedAt || batchData.updatedAt);
  if (batchData.status === 'capturing' && !reprocess) {
    if (lockTimeMs && Date.now() - lockTimeMs < CAPTURE_LOCK_STALE_MS) {
      throw new Error('This batch is already being captured. Please wait for the running capture job to finish.');
    }
  }

  const existingOfficialSnap = await db.collection(COLLECTIONS.snapshots)
    .where('batchId', '==', batchId)
    .where('isOfficial', '==', true)
    .where('status', '==', 'completed')
    .limit(1)
    .get();
  if (!reprocess && !existingOfficialSnap.empty) {
    throw new Error('Official completed snapshots already exist for this batch. Use reprocess to generate a new official set.');
  }

  if (!reprocess && batchData.status === 'completed') {
    throw new Error('Batch is already completed. Use reprocess instead.');
  }

  const captureTimestamp = new Date().toISOString();
  const previousStatus = String(batchData.status || 'active');
  await batchRef.set({
    status: 'capturing',
    captureTimestamp,
    captureStartedAt: captureTimestamp,
    captureRequestedBy: requestedBy,
    captureJobStatus: 'running',
    updatedAt: FieldValue.serverTimestamp(),
  }, { merge: true });

  if (reprocess) {
    await markBatchSnapshotsUnofficial(batchId);
  }

  const jobRef = await db.collection(COLLECTIONS.jobs).add({
    batchId,
    batchNumber: batchData.batchNumber,
    status: 'running',
    mode: reprocess ? 'reprocess' : (requestedBy === 'scheduled' || requestedBy === 'cron' ? 'scheduled' : 'manual'),
    requestedBy,
    startedAt: new Date().toISOString(),
    captureTimestamp,
    processedParticipants: 0,
    successCount: 0,
    failureCount: 0,
    createdAt: FieldValue.serverTimestamp(),
    updatedAt: FieldValue.serverTimestamp(),
  });

  const participants = await listBatchParticipants(batchId);
  let successCount = 0;
  let failureCount = 0;

  try {
    for (const participant of participants) {
      const accountSnap = await db.collection(COLLECTIONS.accounts).doc(String(participant.accountId)).get();
      const account = accountSnap.exists ? { id: accountSnap.id, ...accountSnap.data() } : null;
      const resolvedPlatform = resolveTradingAccountPlatform(account, participant);

      if (
        participant.id
        && isKnownTradingPlatform(resolvedPlatform)
        && shouldReplaceTradingPlatform(participant.platform)
      ) {
        await db.collection(COLLECTIONS.participants).doc(participant.id).set({
          platform: resolvedPlatform,
          updatedAt: FieldValue.serverTimestamp(),
        }, { merge: true });
      }

      const snapshotBase = {
        batchId,
        participantId: participant.id,
        accountId: participant.accountId,
        userId: participant.userId,
        username: participant.username,
        platform: resolvedPlatform,
        batchNumber: batchData.batchNumber,
        joinedAt: participant.joinedAt || participant.startTimestamp,
        captureTimestamp,
        isOfficial: true,
        gainBaselineType: 'starting_balance',
        gainFormulaVersion: 'equity_vs_starting_balance_v1',
        createdAt: FieldValue.serverTimestamp(),
      };

      if (participant.status === 'disqualified') {
        await db.collection(COLLECTIONS.snapshots).add({
          ...snapshotBase,
          status: 'disqualified',
          disqualifiedReason: participant.disqualifiedReason || null,
        });
        continue;
      }

      try {
        if (!account) throw new Error('Trading account not found.');

        const startingBalance = Number(participant.startingBalance || 0);
        const startingEquity = Number(participant.startingEquity || 0);
        if (!Number.isFinite(startingBalance) || startingBalance <= 0) {
          throw new Error('Invalid starting balance.');
        }

        let finalBalance;
        let finalEquity;
        let gainPercent;
        let drawdownAtCapture;
        let drawdownSource;
        let rawApiPayload;
        let captureSource = 'metaapi_rpc';

        try {
          const metaApiInfo = await getMetaApiAccountInfoWithRetry(account, 3);
          finalBalance = Number(metaApiInfo.balance || 0);
          finalEquity = Number(metaApiInfo.equity || 0);
          gainPercent = Number((((finalEquity - startingBalance) / startingBalance) * 100).toFixed(4));
          const ddResolved = resolveDrawdownForPftCapture(metaApiInfo, account);
          drawdownAtCapture = ddResolved.drawdown;
          drawdownSource = ddResolved.drawdownSource;
          rawApiPayload = {
            accountInformation: metaApiInfo,
            drawdownSource,
          };
        } catch (rpcError) {
          const docBalance = Number(account.balance ?? 0);
          const docEquity = Number(account.equity ?? docBalance);
          if (!Number.isFinite(docBalance) || docBalance <= 0) {
            throw rpcError;
          }
          console.warn(
            `[PFT capture] MetaApi RPC failed for account ${participant.accountId}; using tradingAccounts doc fallback:`,
            rpcError instanceof Error ? rpcError.message : rpcError,
          );
          finalBalance = docBalance;
          finalEquity = docEquity;
          gainPercent = Number((((docEquity - startingBalance) / startingBalance) * 100).toFixed(4));
          const ddResolved = resolveDrawdownForPftCapture(null, account);
          drawdownAtCapture = ddResolved.drawdown;
          drawdownSource = ddResolved.drawdownSource || 'account_doc_fallback';
          rawApiPayload = {
            fallback: true,
            captureSource: 'account_doc_fallback',
            drawdownSource,
            metaapi_metrics_synced_at: account.metaapi_metrics_synced_at || null,
            rpcError: rpcError instanceof Error ? rpcError.message : String(rpcError),
          };
          captureSource = 'account_doc_fallback';
        }

        await db.collection(COLLECTIONS.snapshots).add({
          ...snapshotBase,
          startingBalance,
          startingEquity,
          baselineValue: startingBalance,
          finalBalance,
          finalEquity,
          gainPercent,
          drawdownAtCapture,
          drawdownSource: drawdownSource || null,
          captureSource,
          status: 'completed',
          rawApiPayload,
        });

        await db.collection(COLLECTIONS.participants).doc(participant.id).set({
          status: 'completed',
          updatedAt: FieldValue.serverTimestamp(),
        }, { merge: true });

        successCount += 1;
      } catch (error) {
        await db.collection(COLLECTIONS.snapshots).add({
          ...snapshotBase,
          status: 'failed_capture',
          failureKind: isTransientMetaApiError(error) ? 'transient' : 'permanent',
          failureReason: error instanceof Error ? error.message : String(error),
        });
        await db.collection(COLLECTIONS.participants).doc(participant.id).set({
          status: 'failed_capture',
          updatedAt: FieldValue.serverTimestamp(),
        }, { merge: true });
        failureCount += 1;
      }
    }

    await batchRef.set({
      status: 'completed',
      captureTimestamp,
      captureJobStatus: 'completed',
      captureStartedAt: FieldValue.delete(),
      completedAt: new Date().toISOString(),
      updatedAt: FieldValue.serverTimestamp(),
    }, { merge: true });

    const completedBatchSnap = await batchRef.get();
    const completedBatchData = { id: batchId, ...completedBatchSnap.data() };
    const contestId = await ensureBatchHasContest(batchId, completedBatchData, requestedBy);
    await finalizeContestFromSnapshots(batchId, { ...completedBatchData, contestId }, requestedBy);

    await jobRef.set({
      status: 'completed',
      finishedAt: new Date().toISOString(),
      processedParticipants: participants.length,
      successCount,
      failureCount,
      updatedAt: FieldValue.serverTimestamp(),
    }, { merge: true });

    await updateSiteSettings({ pft_last_manual_capture_at: new Date().toISOString() });
    return {
      ok: true,
      jobId: jobRef.id,
      captureTimestamp,
      processedParticipants: participants.length,
      successCount,
      failureCount,
    };
  } catch (error) {
    await batchRef.set({
      status: previousStatus === 'completed' ? 'completed' : 'active',
      captureJobStatus: 'failed',
      captureStartedAt: FieldValue.delete(),
      updatedAt: FieldValue.serverTimestamp(),
    }, { merge: true });

    await jobRef.set({
      status: 'failed',
      error: error instanceof Error ? error.message : String(error),
      finishedAt: new Date().toISOString(),
      processedParticipants: participants.length,
      successCount,
      failureCount,
      updatedAt: FieldValue.serverTimestamp(),
    }, { merge: true });
    throw error;
  }
}

async function pftBatchNumberExists(batchNumber, programId = 'default') {
  const normalized = Number(batchNumber);
  if (!Number.isFinite(normalized)) return false;

  const snap = await db
    .collection(COLLECTIONS.batches)
    .where('batchNumber', '==', normalized)
    .where('programId', '==', programId)
    .limit(1)
    .get();

  return !snap.empty;
}

async function syncProgramBatchesInternal(requestedBy = 'cron') {
  const programRef = db.collection(COLLECTIONS.programs).doc('default');
  const programSnap = await programRef.get();
  if (!programSnap.exists) {
    await ensureDefaultProgram(requestedBy);
  }

  const freshProgramSnap = await programRef.get();
  const program = freshProgramSnap.data();
  if (!program || program.status !== 'active') {
    return { ok: true, created: 0 };
  }

  const existingSnap = await db.collection(COLLECTIONS.batches).get();
  const existingNumbers = new Set(existingSnap.docs.map((item) => Number(item.data().batchNumber)));
  const start = new Date(program.programStartAt);
  const end = new Date(program.programEndAt);
  let cursor = new Date(start);
  let batchNumber = 1;
  let created = 0;

  while (cursor < end) {
    const batchStart = new Date(cursor);
    const batchEnd = new Date(cursor);
    batchEnd.setDate(batchEnd.getDate() + Number(program.batchDurationDays || 14));

    if (!existingNumbers.has(batchNumber)) {
      const batchRef = await db.collection(COLLECTIONS.batches).add({
        programId: 'default',
        batchNumber,
        startAt: batchStart.toISOString(),
        endAt: batchEnd.toISOString(),
        status: batchStart <= new Date() ? 'active' : 'scheduled',
        captureJobStatus: 'queued',
        participantCount: 0,
        createdBy: requestedBy,
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      });
      await ensureBatchHasContest(batchRef.id, {
        batchNumber,
        startAt: batchStart.toISOString(),
        endAt: batchEnd.toISOString(),
        status: batchStart <= new Date() ? 'active' : 'scheduled',
        participantCount: 0,
        createdBy: requestedBy,
      }, requestedBy);
      created += 1;
    }

    cursor.setDate(cursor.getDate() + Number(program.batchFrequencyDays || 14));
    batchNumber += 1;
  }

  await programRef.set({
    currentBatchNumber: batchNumber - 1,
    updatedAt: FieldValue.serverTimestamp(),
  }, { merge: true });

  return { ok: true, created };
}

async function captureEndedBatchesInternal(requestedBy = 'cron') {
  const batchSnap = await db.collection(COLLECTIONS.batches)
    .where('status', 'in', ['scheduled', 'active'])
    .get();

  const now = new Date();
  const endedBatches = batchSnap.docs.filter((item) => new Date(item.data().endAt) <= now);
  let processed = 0;
  for (const batchDoc of endedBatches) {
    await captureBatch(batchDoc.id, requestedBy, false);
    processed += 1;
  }

  return { ok: true, processed };
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'rankedges-pft-backend' });
});

/**
 * Owner-only: triggers server-side MetaApi snapshot (same path as cron) to save browser MetaApi credits.
 */
app.post('/api/meta-api/sync-account/:accountFirestoreId', requireUser, async (req, res) => {
  try {
    const accountFirestoreId = String(req.params.accountFirestoreId || '');
    if (!accountFirestoreId) {
      res.status(400).json({ error: 'accountFirestoreId is required.' });
      return;
    }

    const accountSnap = await db.collection(COLLECTIONS.accounts).doc(accountFirestoreId).get();
    if (!accountSnap.exists) {
      res.status(404).json({ error: 'Trading account not found.' });
      return;
    }

    const data = accountSnap.data();
    if (data.user_id !== req.firebaseUser.uid) {
      res.status(403).json({ error: 'You can only sync your own trading accounts.' });
      return;
    }

    const settingsForTokens = await getSiteSettings();
    const tokenCandidates = resolveMetaApiTokenCandidates({ ...data, id: accountSnap.id }, settingsForTokens);
    if (!data.metaapi_account_id || tokenCandidates.length === 0) {
      res.status(400).json({ error: 'MetaApi credentials missing for this account.' });
      return;
    }

    if (data.metaapi_sync_status === 'running') {
      res.status(409).json({ error: 'A sync is already in progress for this account.' });
      return;
    }

    const account = { id: accountSnap.id, ...data };

    await db.collection(COLLECTIONS.accounts).doc(accountSnap.id).set(
      {
        metaapi_sync_status: 'running',
        metaapi_sync_error: null,
        updatedAt: FieldValue.serverTimestamp(),
      },
      { merge: true },
    );

    const result = await syncMetaApiAccountSnapshot(account, 'user_ui');
    res.json({ ok: true, accountId: accountSnap.id, ...result });
  } catch (error) {
    const accountIdParam = String(req.params.accountFirestoreId || '');
    if (accountIdParam) {
      try {
        forgetAccountThrottleState(accountIdParam);
        const msg = error instanceof Error ? error.message : String(error);
        await db.collection(COLLECTIONS.accounts).doc(accountIdParam).set(
          omitUndefinedFirestoreFields({
            metaapi_sync_status: 'error',
            metaapi_sync_error: msg,
            metaapi_sync_progress: {
              phase: 'error',
              message: msg,
              updatedAt: new Date().toISOString(),
            },
            updatedAt: FieldValue.serverTimestamp(),
          }),
          { merge: true },
        );
      } catch (_) {
        // ignore secondary failure
      }
    }
    res.status(500).json({ error: error instanceof Error ? error.message : 'MetaApi sync failed.' });
  }
});

app.post('/api/meta-api/admin/sync-account', requireAdminPermission('accounts'), async (req, res) => {
  try {
    const accountId = String((req.body && req.body.accountId) || '');
    console.log(`[admin sync] start accountId=${accountId}`);
    if (!accountId) {
      res.status(400).json({ error: 'accountId is required.' });
      return;
    }

    const accountSnap = await db.collection(COLLECTIONS.accounts).doc(accountId).get();
    if (!accountSnap.exists) {
      res.status(404).json({ error: 'Trading account not found.' });
      return;
    }

    const data = accountSnap.data();
    const adminSettings = await getSiteSettings();
    const adminCandidates = resolveMetaApiTokenCandidates({ ...data, id: accountSnap.id }, adminSettings);
    if (!data.metaapi_account_id || adminCandidates.length === 0) {
      res.status(400).json({ error: 'MetaApi credentials missing for this account.' });
      return;
    }

    const account = { id: accountSnap.id, ...data };

    const result = await syncMetaApiAccountSnapshot(account, 'admin_manual', { fullSync: true });
    console.log(`[admin sync] done accountId=${accountId}`, {
      tradesSynced: result.tradesSynced,
      positionsSynced: result.positionsSynced,
    });
    res.json({ ok: true, accountId: accountSnap.id, ...result });
  } catch (error) {
    const aid = String((req.body && req.body.accountId) || '');
    if (aid) {
      try {
        forgetAccountThrottleState(aid);
        const msg = error instanceof Error ? error.message : String(error);
        await db.collection(COLLECTIONS.accounts).doc(aid).set(
          omitUndefinedFirestoreFields({
            metaapi_sync_status: 'error',
            metaapi_sync_error: msg,
            metaapi_sync_progress: {
              phase: 'error',
              message: msg,
              updatedAt: new Date().toISOString(),
            },
            updatedAt: FieldValue.serverTimestamp(),
          }),
          { merge: true },
        );
      } catch (_) {
        /* empty */
      }
    }
    res.status(500).json({ error: error instanceof Error ? error.message : 'MetaApi sync failed.' });
  }
});

app.post('/api/meta-api/admin/sync-all', requireAdminPermission('accounts'), async (_req, res) => {
  try {
    console.log('[admin sync-all] start (direct HTTP, not cron)');
    const summary = await syncAllMetaApiAccountsInternal('admin_manual');
    console.log('[admin sync-all] done', {
      totalAccounts: summary.totalAccounts,
      successCount: summary.results?.filter((r) => r.ok).length,
      failureCount: summary.results?.filter((r) => !r.ok).length,
    });
    res.json(summary);
  } catch (error) {
    await clearAdminBulkSyncProgress();
    res.status(500).json({ error: error instanceof Error ? error.message : 'MetaApi sync-all failed.' });
  }
});

app.post('/api/pft/program/ensure', requireAdmin, async (req, res) => {
  try {
    const result = await ensureDefaultProgram(req.user.uid);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to ensure program.' });
  }
});

app.post('/api/pft/batches', requireAdmin, async (req, res) => {
  try {
    const { batchNumber, startAt, endAt, programId = 'default' } = req.body || {};
    if (batchNumber === undefined || batchNumber === null || batchNumber === '' || !startAt || !endAt) {
      res.status(400).json({ error: 'batchNumber, startAt, and endAt are required.' });
      return;
    }

    const normalizedBatchNumber = Number(batchNumber);
    if (!Number.isInteger(normalizedBatchNumber) || normalizedBatchNumber < 1) {
      res.status(400).json({ error: 'batchNumber must be a positive whole number.' });
      return;
    }

    if (await pftBatchNumberExists(normalizedBatchNumber, programId)) {
      res.status(409).json({
        error: `PFT batch number ${normalizedBatchNumber} already exists. Each batch number must be unique.`,
      });
      return;
    }

    const batchStatus = new Date(startAt) <= new Date() ? 'active' : 'scheduled';
    const ref = await db.collection(COLLECTIONS.batches).add({
      batchNumber: normalizedBatchNumber,
      startAt,
      endAt,
      programId,
      status: batchStatus,
      captureJobStatus: 'queued',
      participantCount: 0,
      createdBy: req.user.uid,
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
    });

    const contestId = await ensureBatchHasContest(ref.id, {
      batchNumber: normalizedBatchNumber,
      startAt,
      endAt,
      status: batchStatus,
      participantCount: 0,
      createdBy: req.user.uid,
    }, req.user.uid);

    res.json({ ok: true, id: ref.id, contestId });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to create batch.' });
  }
});

app.post('/api/pft/batches/:batchId/enroll', requireAdmin, async (req, res) => {
  try {
    const { batchId } = req.params;
    const { accountId } = req.body || {};
    if (!accountId) {
      res.status(400).json({ error: 'accountId is required.' });
      return;
    }

    const batchSnap = await db.collection(COLLECTIONS.batches).doc(batchId).get();
    if (!batchSnap.exists) {
      res.status(404).json({ error: 'PFT batch not found.' });
      return;
    }

    const batch = batchSnap.data();
    if (!['scheduled', 'active'].includes(batch.status)) {
      res.status(400).json({ error: 'Only scheduled or active PFT batches accept participants.' });
      return;
    }

    const accountSnap = await db.collection(COLLECTIONS.accounts).doc(String(accountId)).get();
    if (!accountSnap.exists) {
      res.status(404).json({ error: 'Trading account not found.' });
      return;
    }

    const account = { id: accountSnap.id, ...accountSnap.data() };
    if (account.status !== 'connected') {
      res.status(400).json({ error: 'Trading account must be connected.' });
      return;
    }

    const activeBatchIds = await getActiveBatchIds();
    const duplicatesSnap = await db.collection(COLLECTIONS.participants).where('accountId', '==', String(accountId)).get();
    const duplicates = duplicatesSnap.docs
      .map((item) => ({ id: item.id, ...item.data() }))
      .filter((item) => activeBatchIds.has(item.batchId) && item.batchId !== batchId);
    if (duplicates.length > 0) {
      res.status(400).json({ error: 'This trading account already belongs to another active PFT batch.' });
      return;
    }

    const existingSnap = await db.collection(COLLECTIONS.participants)
      .where('batchId', '==', batchId)
      .where('accountId', '==', String(accountId))
      .get();
    if (!existingSnap.empty) {
      res.status(400).json({ error: 'This trading account is already enrolled in the selected batch.' });
      return;
    }

    const startingBalance = Number(account.balance || 0);
    const startingEquity = Number(account.equity || 0);
    if (!Number.isFinite(startingBalance) || startingBalance <= 0) {
      res.status(400).json({ error: 'Starting balance must be greater than zero.' });
      return;
    }
    if (!Number.isFinite(startingEquity) || startingEquity <= 0) {
      res.status(400).json({ error: 'Starting equity must be greater than zero.' });
      return;
    }

    const userSnap = await db.collection(COLLECTIONS.users).doc(account.user_id).get();
    const username = String(userSnap.data()?.name || userSnap.data()?.displayName || userSnap.data()?.email || account.user_id);
    const nowIso = new Date().toISOString();

    const participantRef = await db.collection(COLLECTIONS.participants).add({
      batchId,
      accountId: String(accountId),
      userId: account.user_id,
      username,
      platform: resolveTradingAccountPlatform(account),
      joinedAt: nowIso,
      startTimestamp: nowIso,
      startingBalance,
      startingEquity,
      status: 'active',
      validationFlags: [],
      createdBy: req.user.uid,
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
    });

    const contestId = await ensureBatchHasContest(batchId, batch, req.user.uid);

    res.json({ ok: true, id: participantRef.id, contestId });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to enroll participant.' });
  }
});

app.get('/api/pft/management/overview', requireAdmin, async (req, res) => {
  try {
    const requestedBatchId = String(req.query.batchId || '').trim();
    const batchLimit = Math.max(1, Math.min(Number(req.query.batchLimit) || 50, 200));
    const jobsLimit = Math.max(1, Math.min(Number(req.query.jobsLimit) || 50, 200));

    const [batchSnap, enrollmentOptions, settings] = await Promise.all([
      db.collection(COLLECTIONS.batches).orderBy('batchNumber', 'desc').limit(batchLimit).get(),
      listPftEnrollmentOptionsFast(),
      getSiteSettings(),
    ]);

    const batches = batchSnap.docs.map((item) => ({ id: item.id, ...item.data() }));

    const selectedBatchId = requestedBatchId || batches[0]?.id || '';
    const selectedBatch = batches.find((item) => item.id === selectedBatchId);
    if (selectedBatchId && selectedBatch?.contestId) {
      await syncPftBatchContestLeaderboard(selectedBatchId, selectedBatch.contestId);
    }

    const [participants, snapshots, jobs] = selectedBatchId
      ? await Promise.all([
        listBatchParticipants(selectedBatchId),
        listBatchSnapshots(selectedBatchId),
        listPftJobs(selectedBatchId, jobsLimit),
      ])
      : [[], [], await listPftJobs('', jobsLimit)];

    const completedSnapshots = snapshots.filter((item) => item.status === 'completed').length;
    const failedSnapshots = snapshots.filter((item) => item.status === 'failed_capture').length;

    res.json({
      ok: true,
      selectedBatchId,
      batches,
      participants,
      snapshots,
      jobs,
      enrollmentOptions,
      completedSnapshots,
      failedSnapshots,
      operationMode: settings.pft_operation_mode || 'admin_manual',
      automationAvailable: Boolean(settings.pft_backend_enabled ?? settings.pft_functions_enabled),
    });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to fetch PFT overview.' });
  }
});

app.post('/api/pft/batches/:batchId/capture', requireAdmin, async (req, res) => {
  try {
    const result = await captureBatch(req.params.batchId, req.user.uid, false);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to capture batch.' });
  }
});

app.post('/api/pft/batches/:batchId/reprocess', requireAdmin, async (req, res) => {
  try {
    const result = await captureBatch(req.params.batchId, req.user.uid, true);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to reprocess batch.' });
  }
});

app.post('/api/pft/top200/rebuild', requireAdmin, async (_req, res) => {
  try {
    const result = await buildTop200();
    res.json({ ...result, message: 'Global PFT Top 200 is deprecated. Rankings live on each batch contest page.' });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to rebuild Top 200.' });
  }
});

app.post('/api/pft/migrate-to-contests', requireAdmin, async (req, res) => {
  try {
    const batchSnap = await db.collection(COLLECTIONS.batches).get();
    const results = [];
    for (const batchDoc of batchSnap.docs) {
      const batchData = batchDoc.data();
      if (batchData.contestId) {
        const sync = await syncPftBatchContestLeaderboard(batchDoc.id, batchData.contestId);
        results.push({
          batchId: batchDoc.id,
          contestId: batchData.contestId,
          skipped: true,
          ...sync,
        });
        continue;
      }
      const migrated = await migratePftBatchToContest(batchDoc, req.user.uid);
      results.push({ ...migrated, skipped: false });
    }
    res.json({ ok: true, migrated: results.filter((item) => !item.skipped).length, results });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to migrate PFT batches.' });
  }
});

app.post('/api/pft/backfill-leaderboard-meta', requireAdmin, async (_req, res) => {
  try {
    const batchSnap = await db.collection(COLLECTIONS.batches).get();
    const results = [];
    for (const batchDoc of batchSnap.docs) {
      const batchData = batchDoc.data();
      if (!batchData.contestId) {
        results.push({ batchId: batchDoc.id, skipped: true, reason: 'no_contest' });
        continue;
      }
      const sync = await syncPftBatchContestLeaderboard(batchDoc.id, batchData.contestId);
      results.push({
        batchId: batchDoc.id,
        contestId: batchData.contestId,
        ...sync,
        skipped: false,
      });
    }
    res.json({
      ok: true,
      totalEnrolled: results.reduce((sum, item) => sum + Number(item.enrolled || 0), 0),
      totalMetaUpdated: results.reduce((sum, item) => sum + Number(item.metaUpdated || 0), 0),
      results,
    });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to backfill PFT leaderboard metadata.' });
  }
});

app.post('/api/pft/contests/:contestId/sync-leaderboard', async (req, res) => {
  try {
    const contestId = String(req.params.contestId || '').trim();
    if (!contestId) {
      res.status(400).json({ error: 'contestId is required.' });
      return;
    }

    const contestSnap = await db.collection(COLLECTIONS.contests).doc(contestId).get();
    if (!contestSnap.exists) {
      res.status(404).json({ error: 'Contest not found.' });
      return;
    }

    const contest = contestSnap.data();
    if (contest.type !== 'pft' || !contest.pft_batch_id) {
      res.status(400).json({ error: 'This contest is not linked to a PFT batch.' });
      return;
    }

    const batchSnap = await db.collection(COLLECTIONS.batches).doc(String(contest.pft_batch_id)).get();
    const batchData = batchSnap.exists ? batchSnap.data() : null;
    const batchStatus = String(batchData?.status || '');

    const sync = await syncPftBatchContestLeaderboard(String(contest.pft_batch_id), contestId);
    res.json({
      ok: true,
      contestId,
      batchId: contest.pft_batch_id,
      batchStatus,
      ...sync,
    });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to sync PFT contest leaderboard.' });
  }
});

app.post('/api/pft/recompute-rankings', requireAdmin, async (req, res) => {
  try {
    const result = await recomputeAllPftContestRankings(req.user.uid);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to recompute PFT rankings.' });
  }
});

app.post('/api/pft/participants/:participantId/disqualify', requireAdmin, async (req, res) => {
  try {
    const { reason } = req.body || {};
    const participantRef = db.collection(COLLECTIONS.participants).doc(req.params.participantId);
    const participantSnap = await participantRef.get();
    if (!participantSnap.exists) {
      res.status(404).json({ error: 'Participant not found.' });
      return;
    }

    const participant = participantSnap.data();
    const normalizedReason = String(reason || 'Manual admin disqualification').trim();
    const batchSnap = participant.batchId
      ? await db.collection(COLLECTIONS.batches).doc(String(participant.batchId)).get()
      : null;
    const batchData = batchSnap?.exists ? batchSnap.data() : null;

    await participantRef.set({
      status: 'disqualified',
      disqualifiedReason: normalizedReason,
      disqualifiedBy: req.user.uid,
      disqualifiedAt: new Date().toISOString(),
      updatedAt: FieldValue.serverTimestamp(),
    }, { merge: true });

    const participantSnapshots = await db.collection(COLLECTIONS.snapshots)
      .where('participantId', '==', req.params.participantId)
      .where('isOfficial', '==', true)
      .get();

    if (!participantSnapshots.empty) {
      const batchWriter = db.batch();
      participantSnapshots.docs.forEach((item) => {
        batchWriter.set(item.ref, {
          isOfficial: false,
          status: 'disqualified',
          disqualifiedReason: normalizedReason,
          updatedAt: FieldValue.serverTimestamp(),
        }, { merge: true });
      });
      await batchWriter.commit();
    }

    if (batchData?.contestId) {
      await disqualifyParticipantInContest(batchData.contestId, {
        ...participant,
        disqualifiedReason: normalizedReason,
      });
    }

    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to disqualify participant.' });
  }
});

app.get('/api/pft/jobs', requireAdmin, async (req, res) => {
  try {
    const batchId = String(req.query.batchId || '').trim();
    const limitValue = Math.max(1, Math.min(Number(req.query.limit) || 50, 200));
    const jobs = await listPftJobs(batchId, limitValue);
    res.json({ ok: true, jobs });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to fetch jobs.' });
  }
});

app.post('/api/pft/cron/sync-batches', requireCronSecret, async (_req, res) => {
  try {
    const result = await syncProgramBatchesInternal('cron');
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to sync batches.' });
  }
});

app.post('/api/pft/cron/capture-ended', requireCronSecret, async (_req, res) => {
  try {
    const result = await captureEndedBatchesInternal('cron');
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to capture ended batches.' });
  }
});

async function processAchievementUser(userId) {
  const { newlyUnlocked } = await achievementEngine.checkAndAwardAchievementsForUser(userId);
  let notificationsSent = 0;

  for (const id of newlyUnlocked) {
    const def = DEFINITION_BY_ID.get(id);
    if (!def) continue;
    const notificationId = await notificationAdmin.createNotification({
      userId,
      type: 'achievement_unlocked',
      title: `Achievement Unlocked: ${def.title}`,
      message: def.description,
      link: '/profile',
    });
    if (notificationId) notificationsSent += 1;
  }

  return { awardsGranted: newlyUnlocked.length, notificationsSent };
}

async function runAchievementCronInternal(requestedBy = 'cron') {
  const summary = {
    requestedBy,
    usersProcessed: 0,
    awardsGranted: 0,
    notificationsSent: 0,
    errors: 0,
  };

  let lastDoc = null;
  const pageSize = ACHIEVEMENT_CRON_PAGE_SIZE;

  while (true) {
    let pageQuery = db
      .collection(COLLECTIONS.users)
      .orderBy(admin.firestore.FieldPath.documentId())
      .limit(pageSize);
    if (lastDoc) {
      pageQuery = pageQuery.startAfter(lastDoc);
    }

    const pageSnap = await pageQuery.get();
    if (pageSnap.empty) break;

    const userIds = pageSnap.docs.map((docSnap) => docSnap.id);

    for (let i = 0; i < userIds.length; i += ACHIEVEMENT_CRON_CONCURRENCY) {
      const chunk = userIds.slice(i, i + ACHIEVEMENT_CRON_CONCURRENCY);
      await Promise.all(
        chunk.map(async (userId) => {
          try {
            const result = await processAchievementUser(userId);
            summary.usersProcessed += 1;
            summary.awardsGranted += result.awardsGranted;
            summary.notificationsSent += result.notificationsSent;
          } catch (error) {
            summary.errors += 1;
            console.error(
              `[achievement-cron] user ${userId}:`,
              error instanceof Error ? error.message : error,
            );
          }
        }),
      );
    }

    lastDoc = pageSnap.docs[pageSnap.docs.length - 1];
    if (pageSnap.size < pageSize) break;
  }

  return summary;
}

app.post('/api/cron/check-achievements', requireCronSecret, async (_req, res) => {
  try {
    const result = await runAchievementCronInternal('http');
    res.json({ ok: true, ...result });
  } catch (error) {
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Failed to run achievement cron.',
    });
  }
});

function wrapCronTask(taskName, lockKey, handler) {
  return async () => {
    if (schedulerState[lockKey]) {
      console.log(`skipped ${taskName}; previous run still active.`);
      return;
    }

    schedulerState[lockKey] = true;
    const startedAt = Date.now();
    console.log(`started ${taskName}.`);
    try {
      const result = await handler();
      const elapsedMs = Date.now() - startedAt;
      console.log(`completed ${taskName} in ${elapsedMs}ms`, result);
    } catch (error) {
      console.error(`failed ${taskName}:`, error instanceof Error ? error.message : error);
    } finally {
      schedulerState[lockKey] = false;
    }
  };
}

function startAchievementCronScheduler() {
  if (!ACHIEVEMENT_CRON_ENABLED) {
    console.log('Achievement cron disabled. Set ACHIEVEMENT_CRON_ENABLED=true to enable.');
    return;
  }

  if (!cron.validate(ACHIEVEMENT_CRON_SCHEDULE)) {
    console.error(`Invalid achievement cron schedule: ${ACHIEVEMENT_CRON_SCHEDULE}`);
    return;
  }

  cron.schedule(
    ACHIEVEMENT_CRON_SCHEDULE,
    wrapCronTask('check-achievements', 'achievementCronRunning', () =>
      runAchievementCronInternal('scheduled'),
    ),
    { timezone: ACHIEVEMENT_CRON_TIMEZONE },
  );

  console.log(
    `Achievement cron enabled (timezone=${ACHIEVEMENT_CRON_TIMEZONE}, schedule='${ACHIEVEMENT_CRON_SCHEDULE}', concurrency=${ACHIEVEMENT_CRON_CONCURRENCY}).`,
  );
}

function startInternalCronScheduler() {
  if (INTERNAL_CRON_ENABLED) {
    if (!cron.validate(INTERNAL_CRON_SYNC_SCHEDULE)) {
      console.error(`Invalid sync schedule expression: ${INTERNAL_CRON_SYNC_SCHEDULE}`);
    } else if (!cron.validate(INTERNAL_CRON_CAPTURE_SCHEDULE)) {
      console.error(`Invalid capture schedule expression: ${INTERNAL_CRON_CAPTURE_SCHEDULE}`);
    } else {
      cron.schedule(
        INTERNAL_CRON_SYNC_SCHEDULE,
        wrapCronTask('sync-metaapi', 'syncRunning', () => syncAllMetaApiAccountsInternal('scheduled')),
        { timezone: INTERNAL_CRON_TIMEZONE },
      );

      cron.schedule(
        INTERNAL_CRON_CAPTURE_SCHEDULE,
        wrapCronTask('capture-ended', 'captureRunning', () => captureEndedBatchesInternal('scheduled')),
        { timezone: INTERNAL_CRON_TIMEZONE },
      );

      if (cron.validate(INTERNAL_CRON_PFT_LIVE_SCHEDULE)) {
        cron.schedule(
          INTERNAL_CRON_PFT_LIVE_SCHEDULE,
          wrapCronTask('pft-live-leaderboard', 'pftLiveRunning', () => refreshActivePftLiveLeaderboards()),
          { timezone: INTERNAL_CRON_TIMEZONE },
        );
      } else {
        console.error(`Invalid PFT live leaderboard schedule: ${INTERNAL_CRON_PFT_LIVE_SCHEDULE}`);
      }

      console.log(
        `PFT internal scheduler enabled (timezone=${INTERNAL_CRON_TIMEZONE}, sync='${INTERNAL_CRON_SYNC_SCHEDULE}', capture='${INTERNAL_CRON_CAPTURE_SCHEDULE}', live='${INTERNAL_CRON_PFT_LIVE_SCHEDULE}').`,
      );
    }
  } else {
    console.log('PFT internal scheduler disabled. Set PFT_CRON_ENABLED=true to enable.');
  }

  startAchievementCronScheduler();

  scheduleContestLifecycleCron(
    db,
    (contestId) => startContestAdmin(db, contestId),
    notificationAdmin,
  );
}

app.listen(PORT, () => {
  console.log(`Rankedges PFT backend listening on port ${PORT}`);
  startInternalCronScheduler();
});
