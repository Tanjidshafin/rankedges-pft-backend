require('dotenv').config()
const express = require('express');
const cors = require('cors');
const cron = require('node-cron');
const admin = require('firebase-admin');
const app = express();
const PORT = Number(process.env.PORT || 3001);
const DEFAULT_TOP_200_SIZE = 200;
const CAPTURE_LOCK_STALE_MS = Number(process.env.PFT_CAPTURE_LOCK_STALE_MS || 2 * 60 * 60 * 1000);
const INTERNAL_CRON_ENABLED = String(process.env.PFT_CRON_ENABLED || 'false').toLowerCase() === 'true';
const INTERNAL_CRON_TIMEZONE = process.env.PFT_CRON_TIMEZONE || 'UTC';
const INTERNAL_CRON_SYNC_SCHEDULE = process.env.PFT_CRON_SYNC_SCHEDULE || '0 0,12 * * *';
const INTERNAL_CRON_CAPTURE_SCHEDULE = process.env.PFT_CRON_CAPTURE_SCHEDULE || '5 0 * * *';

const schedulerState = {
  syncRunning: false,
  captureRunning: false,
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
const FieldValue = admin.firestore.FieldValue;

app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map((item) => item.trim()).filter(Boolean);
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      callback(null, true);
      return;
    }
    callback(new Error('Origin not allowed by CORS.'));
  },
  credentials: true,
}));
app.use(express.json({ limit: '2mb' }));

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
};

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

async function getSiteSettings() {
  const snap = await db.collection(COLLECTIONS.settings).doc(SETTINGS_DOC_ID).get();
  return snap.exists ? snap.data() : {};
}

async function updateSiteSettings(partial) {
  await db.collection(COLLECTIONS.settings).doc(SETTINGS_DOC_ID).set(partial, { merge: true });
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

async function getMetaApiAccountInfo(account) {
  const settings = await getSiteSettings();
  const token = account.metaapi_token || process.env.METAAPI_TOKEN || settings.metaapi_token;
  if (!account.metaapi_account_id || !token) {
    throw new Error(`MetaApi credentials missing for account ${account.login || account.id || account.metaapi_account_id}.`);
  }

  const regionResponse = await fetch(
    `https://mt-provisioning-api-v1.agiliumtrade.agiliumtrade.ai/users/current/accounts/${account.metaapi_account_id}`,
    {
      headers: {
        'auth-token': token,
        'Content-Type': 'application/json',
      },
    },
  );

  if (!regionResponse.ok) {
    throw new Error(`MetaApi account-details request failed with ${regionResponse.status}.`);
  }

  const regionPayload = await regionResponse.json();
  const region = account.metaapi_region || regionPayload.region || 'new-york';
  const clientApiUrl = `https://mt-client-api-v1.${region}.agiliumtrade.ai`;
  const infoResponse = await fetch(
    `${clientApiUrl}/users/current/accounts/${account.metaapi_account_id}/account-information`,
    {
      headers: {
        'auth-token': token,
        'Content-Type': 'application/json',
      },
    },
  );

  if (!infoResponse.ok) {
    throw new Error(`MetaApi account-info request failed with ${infoResponse.status}.`);
  }

  return infoResponse.json();
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
  const chunks = chunkArray(docs, 400);
  for (const chunk of chunks) {
    const batch = db.batch();
    chunk.forEach(({ id, data }) => {
      batch.set(db.collection(collectionName).doc(id), data, { merge: false });
    });
    await batch.commit();
  }
}

async function fetchMetaApiAccountDetails(accountId, token) {
  const response = await fetch(`https://mt-provisioning-api-v1.agiliumtrade.agiliumtrade.ai/users/current/accounts/${accountId}`, {
    headers: {
      'auth-token': token,
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`MetaApi account-details request failed with ${response.status}.`);
  }

  return response.json();
}

function getClientApiUrl(region = 'new-york') {
  return `https://mt-client-api-v1.${region}.agiliumtrade.ai`;
}

async function fetchMetaApiAccountInfo(account, token, region) {
  const resolvedRegion = region || account.metaapi_region || 'new-york';
  const clientApiUrl = getClientApiUrl(resolvedRegion);
  const response = await fetch(
    `${clientApiUrl}/users/current/accounts/${account.metaapi_account_id}/account-information`,
    {
      headers: {
        'auth-token': token,
        'Content-Type': 'application/json',
      },
    },
  );

  if (!response.ok) {
    throw new Error(`MetaApi account-info request failed with ${response.status}.`);
  }

  return response.json();
}

async function fetchMetaApiTrades(account, token, startTime, endTime, region) {
  const resolvedRegion = region || account.metaapi_region || 'new-york';
  const clientApiUrl = getClientApiUrl(resolvedRegion);
  const start = startTime || new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
  const end = endTime || new Date().toISOString();
  const response = await fetch(
    `${clientApiUrl}/users/current/accounts/${account.metaapi_account_id}/history-deals/time/${encodeURIComponent(start)}/${encodeURIComponent(end)}`,
    {
      headers: {
        'auth-token': token,
        'Content-Type': 'application/json',
      },
    },
  );

  if (!response.ok) {
    throw new Error(`MetaApi trades request failed with ${response.status}.`);
  }

  return response.json();
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
    throw new Error(`MetaApi positions request failed with ${response.status}.`);
  }

  return response.json();
}

async function syncMetaApiAccountSnapshot(account, requestedBy = 'scheduled') {
  const settings = await getSiteSettings();
  const token = account.metaapi_token || process.env.METAAPI_TOKEN || settings.metaapi_token;
  if (!account.metaapi_account_id || !token) {
    throw new Error(`MetaApi credentials missing for account ${account.login || account.id || account.metaapi_account_id}.`);
  }

  const regionPayload = await fetchMetaApiAccountDetails(account.metaapi_account_id, token);
  const region = account.metaapi_region || regionPayload.region || 'new-york';
  const accountInfo = await fetchMetaApiAccountInfo(account, token, region);
  const rawDeals = await fetchMetaApiTrades(account, token, undefined, undefined, region);
  const rawPositions = await fetchMetaApiPositions(account, token, region);

  const nowIso = new Date().toISOString();
  const syncRunId = `${account.id || account.metaapi_account_id}-${Date.now()}`;

  const normalizedDeals = (Array.isArray(rawDeals) ? rawDeals : []).map((deal) => ({
    id: `${account.id || account.metaapi_account_id}_${deal.id}`,
    data: {
      user_id: account.user_id,
      account_id: account.id || account.metaapi_account_id,
      account_login: account.login || '',
      symbol: deal.symbol,
      type: deal.type,
      volume: Number(deal.volume || 0),
      openPrice: Number(deal.price || 0),
      closePrice: Number(deal.price || 0),
      profit: Number(deal.profit || 0),
      openTime: deal.time,
      closeTime: deal.time,
      swap: Number(deal.swap || 0),
      commission: Number(deal.commission || 0),
      comment: deal.comment || null,
      metaapi_account_id: account.metaapi_account_id,
      metaapi_region: region,
      synced_at: nowIso,
      sync_run_id: syncRunId,
      createdAt: FieldValue.serverTimestamp(),
    },
  }));

  const normalizedPositions = (Array.isArray(rawPositions) ? rawPositions : []).map((position) => ({
    id: `${account.id || account.metaapi_account_id}_${position.id}`,
    data: {
      user_id: account.user_id,
      account_id: account.id || account.metaapi_account_id,
      account_login: account.login || '',
      symbol: position.symbol,
      type: position.type,
      volume: Number(position.volume || 0),
      openPrice: Number(position.openPrice || 0),
      currentPrice: Number(position.currentPrice || 0),
      profit: Number(position.profit || 0),
      openTime: position.openTime,
      swap: Number(position.swap || 0),
      commission: Number(position.commission || 0),
      metaapi_account_id: account.metaapi_account_id,
      metaapi_region: region,
      synced_at: nowIso,
      sync_run_id: syncRunId,
      createdAt: FieldValue.serverTimestamp(),
    },
  }));

  await deleteDocumentsByField(COLLECTIONS.metaApiTrades, 'account_id', account.id || account.metaapi_account_id);
  await deleteDocumentsByField(COLLECTIONS.metaApiPositions, 'account_id', account.id || account.metaapi_account_id);

  await writeDocuments(COLLECTIONS.metaApiTrades, normalizedDeals);
  await writeDocuments(COLLECTIONS.metaApiPositions, normalizedPositions);

  const totalProfit = normalizedDeals.reduce((sum, item) => sum + Number(item.data.profit || 0), 0);
  const totalTrades = normalizedDeals.filter((item) => ['DEAL_TYPE_BUY', 'DEAL_TYPE_SELL'].includes(item.data.type)).length;
  const initialBalance = Number(accountInfo.balance || 0) - totalProfit;
  const gain = Number.isFinite(initialBalance) && initialBalance > 0 ? Number(((totalProfit / initialBalance) * 100).toFixed(2)) : 0;

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
    metaapi_account_id: account.metaapi_account_id,
    metaapi_region: region,
    synced_at: nowIso,
    sync_run_id: syncRunId,
    createdAt: FieldValue.serverTimestamp(),
  };

  await db.collection(COLLECTIONS.metaApiAccountSnapshots).doc(String(account.id || account.metaapi_account_id)).set(accountSnapshot, { merge: false });
  await db.collection(COLLECTIONS.accounts).doc(String(account.id || account.metaapi_account_id)).set({
    balance: Number(accountInfo.balance || 0),
    equity: Number(accountInfo.equity || 0),
    gain,
    dd: Number(account.dd || 0),
    profit: Number(totalProfit.toFixed(2)),
    win_rate: Number(account.win_rate || 0),
    total_trades: totalTrades,
    metaapi_region: region,
    last_metaapi_sync_at: nowIso,
    metaapi_sync_status: 'success',
    metaapi_sync_error: null,
    metaapi_snapshot_version: FieldValue.increment(1),
    updatedAt: FieldValue.serverTimestamp(),
  }, { merge: true });

  return {
    accountId: account.id || account.metaapi_account_id,
    syncRunId,
    tradesSynced: normalizedDeals.length,
    positionsSynced: normalizedPositions.length,
    requestedBy,
    syncedAt: nowIso,
  };
}

async function syncAllMetaApiAccountsInternal(requestedBy = 'scheduled') {
  const accountsSnap = await db.collection(COLLECTIONS.accounts)
    .where('status', '==', 'connected')
    .get();

  const results = [];
  for (const accountDoc of accountsSnap.docs) {
    const account = { id: accountDoc.id, ...accountDoc.data() };
    if (!account.metaapi_account_id || !account.metaapi_token) {
      continue;
    }

    try {
      await db.collection(COLLECTIONS.accounts).doc(accountDoc.id).set({
        metaapi_sync_status: 'running',
        metaapi_sync_error: null,
        updatedAt: FieldValue.serverTimestamp(),
      }, { merge: true });

      const result = await syncMetaApiAccountSnapshot(account, requestedBy);
      results.push({ ok: true, ...result });
    } catch (error) {
      await db.collection(COLLECTIONS.accounts).doc(accountDoc.id).set({
        metaapi_sync_status: 'error',
        metaapi_sync_error: error instanceof Error ? error.message : String(error),
        updatedAt: FieldValue.serverTimestamp(),
      }, { merge: true });
      results.push({ ok: false, accountId: accountDoc.id, error: error instanceof Error ? error.message : String(error) });
    }
  }

  await db.collection(COLLECTIONS.metaApiSyncRuns).add({
    requestedBy,
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    totalAccounts: accountsSnap.size,
    successCount: results.filter((item) => item.ok).length,
    failureCount: results.filter((item) => !item.ok).length,
    results,
    createdAt: FieldValue.serverTimestamp(),
  });

  return { ok: true, totalAccounts: accountsSnap.size, results };
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

function isParticipantRankEligible(status) {
  return status !== 'disqualified' && status !== 'invalid';
}

function chunkArray(items, size) {
  const chunks = [];
  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size));
  }
  return chunks;
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
      platform: account.platform || 'unknown',
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

async function buildTop200() {
  const snapshotsSnap = await db.collection(COLLECTIONS.snapshots)
    .where('isOfficial', '==', true)
    .where('status', '==', 'completed')
    .get();

  const snapshotRows = snapshotsSnap.docs.map((item) => ({ id: item.id, ...item.data() }));
  const participantsById = await getParticipantsByIds(snapshotRows.map((item) => item.participantId));

  const eligibleSnapshots = snapshotRows.filter((snapshot) => {
    const participant = participantsById.get(String(snapshot.participantId || ''));
    if (!participant) return false;
    if (!isParticipantRankEligible(String(participant.status || ''))) return false;
    if (!Number.isFinite(Number(snapshot.gainPercent))) return false;
    return true;
  });

  const officialSnapshots = sortSnapshotsForLeaderboard(eligibleSnapshots);

  const nextEntries = officialSnapshots.slice(0, DEFAULT_TOP_200_SIZE);
  const currentTopSnap = await db.collection(COLLECTIONS.top200).get();
  const currentEntries = currentTopSnap.docs.map((item) => ({ id: item.id, ...item.data() }));
  const currentByAccount = new Map(currentEntries.map((item) => [item.accountId, item]));
  const nextAccountIds = new Set(nextEntries.map((item) => item.accountId));
  const nowIso = new Date().toISOString();

  const batchWriter = db.batch();
  currentTopSnap.docs.forEach((item) => batchWriter.delete(item.ref));

  nextEntries.forEach((snapshot, index) => {
    const rankPosition = index + 1;
    const previous = currentByAccount.get(snapshot.accountId);
    const ref = db.collection(COLLECTIONS.top200).doc(String(snapshot.accountId));

    batchWriter.set(ref, {
      rankPosition,
      accountId: snapshot.accountId,
      participantId: snapshot.participantId,
      snapshotId: snapshot.id,
      batchId: snapshot.batchId,
      batchNumber: snapshot.batchNumber,
      userId: snapshot.userId,
      username: snapshot.username,
      platform: snapshot.platform,
      gainPercent: snapshot.gainPercent,
      finalEquity: snapshot.finalEquity,
      capturedAt: snapshot.captureTimestamp,
      joinedAt: snapshot.joinedAt,
      status: 'active',
      isNewEntry: !previous,
      maskedAccountRef: maskAccountReference(snapshot.accountId),
      createdAt: previous?.createdAt || FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
    }, { merge: true });

    if (!previous || previous.rankPosition !== rankPosition || previous.snapshotId !== snapshot.id) {
      batchWriter.set(db.collection(COLLECTIONS.top200History).doc(), {
        leaderboardEntryId: ref.id,
        accountId: snapshot.accountId,
        batchId: snapshot.batchId,
        batchNumber: snapshot.batchNumber,
        rankPosition,
        gainPercent: snapshot.gainPercent,
        actionType: previous ? 'updated' : 'inserted',
        actionTimestamp: nowIso,
        username: snapshot.username,
        createdAt: FieldValue.serverTimestamp(),
      });
    }
  });

  currentEntries
    .filter((entry) => !nextAccountIds.has(entry.accountId))
    .forEach((entry) => {
      batchWriter.set(db.collection(COLLECTIONS.top200History).doc(), {
        leaderboardEntryId: entry.id,
        accountId: entry.accountId,
        batchId: entry.batchId,
        batchNumber: entry.batchNumber,
        rankPosition: entry.rankPosition,
        gainPercent: entry.gainPercent,
        actionType: 'removed',
        actionTimestamp: nowIso,
        username: entry.username,
        createdAt: FieldValue.serverTimestamp(),
      });
    });

  await batchWriter.commit();
  await updateSiteSettings({ pft_last_top200_refresh_at: new Date().toISOString() });
  return { ok: true, total: nextEntries.length };
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
      const snapshotBase = {
        batchId,
        participantId: participant.id,
        accountId: participant.accountId,
        userId: participant.userId,
        username: participant.username,
        platform: participant.platform || 'unknown',
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
        const accountSnap = await db.collection(COLLECTIONS.accounts).doc(String(participant.accountId)).get();
        if (!accountSnap.exists) throw new Error('Trading account not found.');

        const account = { id: accountSnap.id, ...accountSnap.data() };
        const startingBalance = Number(participant.startingBalance || 0);
        const startingEquity = Number(participant.startingEquity || 0);
        if (!Number.isFinite(startingBalance) || startingBalance <= 0) {
          throw new Error('Invalid starting balance.');
        }

        const metaApiInfo = await getMetaApiAccountInfoWithRetry(account, 3);
        const finalBalance = Number(metaApiInfo.balance || 0);
        const finalEquity = Number(metaApiInfo.equity || 0);
        const gainPercent = Number((((finalEquity - startingBalance) / startingBalance) * 100).toFixed(4));
        const drawdownAtCapture = resolveDrawdownAtCapture(metaApiInfo);

        await db.collection(COLLECTIONS.snapshots).add({
          ...snapshotBase,
          startingBalance,
          startingEquity,
          baselineValue: startingBalance,
          finalBalance,
          finalEquity,
          gainPercent,
          drawdownAtCapture,
          status: 'completed',
          rawApiPayload: metaApiInfo,
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
      await db.collection(COLLECTIONS.batches).add({
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
    await buildTop200();
    processed += 1;
  }

  return { ok: true, processed };
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'rankedges-pft-backend' });
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
    if (!batchNumber || !startAt || !endAt) {
      res.status(400).json({ error: 'batchNumber, startAt, and endAt are required.' });
      return;
    }

    const ref = await db.collection(COLLECTIONS.batches).add({
      batchNumber: Number(batchNumber),
      startAt,
      endAt,
      programId,
      status: new Date(startAt) <= new Date() ? 'active' : 'scheduled',
      captureJobStatus: 'queued',
      participantCount: 0,
      createdBy: req.user.uid,
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
    });

    res.json({ ok: true, id: ref.id });
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
      platform: account.platform || 'unknown',
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

    await db.collection(COLLECTIONS.batches).doc(batchId).set({
      participantCount: Number(batch.participantCount || 0) + 1,
      updatedAt: FieldValue.serverTimestamp(),
    }, { merge: true });

    res.json({ ok: true, id: participantRef.id });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to enroll participant.' });
  }
});

app.get('/api/pft/management/overview', requireAdmin, async (req, res) => {
  try {
    const requestedBatchId = String(req.query.batchId || '').trim();
    const batchLimit = Math.max(1, Math.min(Number(req.query.batchLimit) || 50, 200));
    const topLimit = Math.max(1, Math.min(Number(req.query.topLimit) || DEFAULT_TOP_200_SIZE, 500));
    const historyLimit = Math.max(1, Math.min(Number(req.query.historyLimit) || 200, 500));
    const jobsLimit = Math.max(1, Math.min(Number(req.query.jobsLimit) || 50, 200));

    const [batchSnap, topSnap, historySnap, enrollmentOptions, settings] = await Promise.all([
      db.collection(COLLECTIONS.batches).orderBy('batchNumber', 'desc').limit(batchLimit).get(),
      db.collection(COLLECTIONS.top200).orderBy('rankPosition', 'asc').limit(topLimit).get(),
      db.collection(COLLECTIONS.top200History).orderBy('actionTimestamp', 'desc').limit(historyLimit).get(),
      listPftEnrollmentOptionsFast(),
      getSiteSettings(),
    ]);

    const batches = batchSnap.docs.map((item) => ({ id: item.id, ...item.data() }));
    const top200 = topSnap.docs.map((item) => ({ id: item.id, ...item.data() }));
    const history = historySnap.docs.map((item) => ({ id: item.id, ...item.data() }));

    const selectedBatchId = requestedBatchId || batches[0]?.id || '';

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
      top200,
      history,
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
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to rebuild Top 200.' });
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

    await db.collection(COLLECTIONS.top200History).add({
      accountId: participant.accountId || null,
      participantId: req.params.participantId,
      batchId: participant.batchId || null,
      batchNumber: participant.batchNumber || null,
      rankPosition: null,
      gainPercent: null,
      actionType: 'removed',
      actionReason: 'manual_disqualification',
      actionTimestamp: new Date().toISOString(),
      actedBy: req.user.uid,
      reason: normalizedReason,
      username: participant.username || null,
      createdAt: FieldValue.serverTimestamp(),
    });

    await buildTop200();
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

function startInternalCronScheduler() {
  if (!INTERNAL_CRON_ENABLED) {
    console.log('Internal scheduler disabled. Set PFT_CRON_ENABLED=true to enable.');
    return;
  }

  if (!cron.validate(INTERNAL_CRON_SYNC_SCHEDULE)) {
    console.error(`Invalid sync schedule expression: ${INTERNAL_CRON_SYNC_SCHEDULE}`);
    return;
  }
  if (!cron.validate(INTERNAL_CRON_CAPTURE_SCHEDULE)) {
    console.error(`Invalid capture schedule expression: ${INTERNAL_CRON_CAPTURE_SCHEDULE}`);
    return;
  }

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

  console.log(
    `Internal scheduler enabled (timezone=${INTERNAL_CRON_TIMEZONE}, sync='${INTERNAL_CRON_SYNC_SCHEDULE}', capture='${INTERNAL_CRON_CAPTURE_SCHEDULE}').`,
  );
}

app.listen(PORT, () => {
  console.log(`Rankedges PFT backend listening on port ${PORT}`);
  startInternalCronScheduler();
});
