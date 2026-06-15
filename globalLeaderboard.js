/**
 * Global leaderboard sync + rerank (server-side).
 */

const admin = require('firebase-admin');

const GLOBAL_LEADERBOARD_CONTEST_ID = '__global__';

const GLOBAL_LEADERBOARD_CATEGORIES = [
  'highest_gain',
  'highest_profit',
  'most_lots',
  'best_risk_adjusted',
  'highest_balance',
];

function asFiniteNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function scoreForCategory(category, account, totalLot) {
  switch (category) {
    case 'highest_gain':
      return asFiniteNumber(account.gain, 0);
    case 'highest_profit':
      return asFiniteNumber(account.profit, 0);
    case 'most_lots':
      return asFiniteNumber(totalLot, 0);
    case 'highest_balance':
      return asFiniteNumber(account.balance, 0);
    case 'best_risk_adjusted': {
      const gain = asFiniteNumber(account.gain, 0);
      const dd = asFiniteNumber(account.dd, 0);
      const penalty = dd > 0 ? Math.max(0.1, 1 - dd / 100) : 1;
      return gain * penalty;
    }
    default:
      return 0;
  }
}

function compareGlobalLeaderboardEntries(left, right) {
  const scoreDiff = asFiniteNumber(right.score, 0) - asFiniteNumber(left.score, 0);
  if (scoreDiff !== 0) return scoreDiff;
  const gainDiff = asFiniteNumber(right.gain, 0) - asFiniteNumber(left.gain, 0);
  if (gainDiff !== 0) return gainDiff;
  const profitDiff = asFiniteNumber(right.profit, 0) - asFiniteNumber(left.profit, 0);
  if (profitDiff !== 0) return profitDiff;
  return asFiniteNumber(left.dd, 0) - asFiniteNumber(right.dd, 0);
}

async function sumAccountLots(db, accountId) {
  const snap = await db.collection('metaApiTrades').where('account_id', '==', String(accountId)).get();
  let lots = 0;
  for (const docSnap of snap.docs) {
    const vol = Number(docSnap.data().volume ?? 0);
    if (Number.isFinite(vol)) lots += vol;
  }
  return Number(lots.toFixed(2));
}

async function rerankGlobalLeaderboardServer(db) {
  const snap = await db
    .collection('leaderboard')
    .where('contest_id', '==', GLOBAL_LEADERBOARD_CONTEST_ID)
    .get();

  const allEntries = snap.docs.map((docSnap) => ({ id: docSnap.id, ...docSnap.data() }));
  const batch = db.batch();
  let updates = 0;

  for (const category of GLOBAL_LEADERBOARD_CATEGORIES) {
    const inCategory = allEntries.filter(
      (entry) => entry.category === category && Number.isFinite(Number(entry.score)),
    );
    const sorted = [...inCategory].sort(compareGlobalLeaderboardEntries);

    sorted.forEach((entry, index) => {
      const nextRank = index + 1;
      if (!entry.id || entry.rank === nextRank) return;
      batch.set(
        db.collection('leaderboard').doc(entry.id),
        { rank: nextRank, updatedAt: admin.firestore.FieldValue.serverTimestamp() },
        { merge: true },
      );
      updates += 1;
    });
  }

  if (updates > 0) {
    await batch.commit();
  }

  return { categories: GLOBAL_LEADERBOARD_CATEGORIES.length, rankUpdates: updates };
}

async function syncGlobalLeaderboardForUserServer(db, userId, profile) {
  const prefs = profile?.globalLeaderboard || { enabled: false, categories: [], accountIds: [] };
  const traderName = prefs.displayName?.trim() || profile?.name || 'Trader';
  const country = profile?.country || '';
  const avatar = profile?.avatar;

  const existingSnap = await db
    .collection('leaderboard')
    .where('contest_id', '==', GLOBAL_LEADERBOARD_CONTEST_ID)
    .where('user_id', '==', String(userId))
    .get();

  const deleteBatch = db.batch();
  existingSnap.docs.forEach((docSnap) => deleteBatch.delete(docSnap.ref));
  if (!existingSnap.empty) {
    await deleteBatch.commit();
  }

  if (!prefs.enabled || !Array.isArray(prefs.categories) || prefs.categories.length === 0) {
    return { userId, entries: 0, skipped: true };
  }

  const accountIds = Array.isArray(prefs.accountIds) ? prefs.accountIds.map(String) : [];
  if (accountIds.length === 0) {
    return { userId, entries: 0, skipped: true };
  }

  let entriesWritten = 0;

  for (const accountId of accountIds) {
    const accountSnap = await db.collection('tradingAccounts').doc(accountId).get();
    if (!accountSnap.exists) continue;
    const account = { id: accountSnap.id, ...accountSnap.data() };
    if (String(account.user_id) !== String(userId)) continue;
    if (String(account.status || '') !== 'connected') continue;

    const totalLot = await sumAccountLots(db, accountId);

    for (const category of prefs.categories) {
      if (!GLOBAL_LEADERBOARD_CATEGORIES.includes(category)) continue;

      const score = scoreForCategory(category, account, totalLot);
      if (!Number.isFinite(score)) continue;

      await db.collection('leaderboard').add({
        contest_id: GLOBAL_LEADERBOARD_CONTEST_ID,
        scope: 'global',
        category,
        account_id: accountId,
        user_id: String(userId),
        trader_name: traderName,
        trader_avatar: avatar,
        country,
        gain: asFiniteNumber(account.gain, 0),
        dd: asFiniteNumber(account.dd, 0),
        profit: asFiniteNumber(account.profit, 0),
        balance: asFiniteNumber(account.balance, 0),
        equity: asFiniteNumber(account.equity, account.balance),
        total_lot: totalLot,
        rank: 0,
        score,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      entriesWritten += 1;
    }
  }

  return { userId, entries: entriesWritten, skipped: false };
}

async function refreshGlobalLeaderboardsInternal(db) {
  const usersSnap = await db.collection('users').where('globalLeaderboard.enabled', '==', true).get();
  const results = [];

  for (const userDoc of usersSnap.docs) {
    try {
      const result = await syncGlobalLeaderboardForUserServer(db, userDoc.id, userDoc.data());
      results.push(result);
    } catch (error) {
      results.push({
        userId: userDoc.id,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const rerank = await rerankGlobalLeaderboardServer(db);

  return {
    ok: true,
    users: usersSnap.size,
    rerank,
    results,
  };
}

module.exports = {
  GLOBAL_LEADERBOARD_CONTEST_ID,
  GLOBAL_LEADERBOARD_CATEGORIES,
  refreshGlobalLeaderboardsInternal,
  syncGlobalLeaderboardForUserServer,
  rerankGlobalLeaderboardServer,
};
