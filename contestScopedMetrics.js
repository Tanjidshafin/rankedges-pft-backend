/**
 * Contest-window metrics from persisted Firestore trades (server-side).
 */

const { buildLeaderboardMetricUpdate, resolveGainBasis } = require('./contestGainMetrics');
const { resolveLeaderboardScore } = require('./contestRanking');
const {
  deriveMetricsFromFirestoreTradeDocs,
  firestoreTradeDocToSnapshot,
} = require('./metaApiDealUtils');

function getContestRangeEndIso(contest) {
  const contestEndMs = new Date(contest.end_at || '').getTime();
  if (Number.isNaN(contestEndMs)) {
    return new Date().toISOString();
  }
  return new Date(Math.min(Date.now(), contestEndMs)).toISOString();
}

function tradeTimeMs(trade) {
  const raw = trade.closeTime || trade.openTime;
  if (raw == null || raw === '') return Number.NaN;
  const ms = new Date(raw).getTime();
  return Number.isFinite(ms) ? ms : Number.NaN;
}

function filterTradesInRange(tradeDocs, startIso, endIso) {
  const startMs = new Date(startIso).getTime();
  const endMs = new Date(endIso).getTime();
  if (Number.isNaN(startMs) || Number.isNaN(endMs) || startMs > endMs) {
    return [];
  }

  return tradeDocs
    .map((row) => firestoreTradeDocToSnapshot(row))
    .filter((trade) => {
      const tradeMs = tradeTimeMs(trade);
      return Number.isFinite(tradeMs) && tradeMs >= startMs && tradeMs <= endMs;
    });
}

function sumTotalLot(trades) {
  let totalLot = 0;
  for (const trade of trades) {
    if (trade.type !== 'DEAL_TYPE_BUY' && trade.type !== 'DEAL_TYPE_SELL') continue;
    totalLot += Number(trade.volume || 0);
  }
  return Number(totalLot.toFixed(2));
}

function buildContestScopedMetrics(contest, account, entry, tradeDocs) {
  const gainBasis = resolveGainBasis(contest);
  const needsLotData = contest.type === 'standard' || gainBasis === 'balance';
  const base = buildLeaderboardMetricUpdate({ contest, account, entry });

  if (!needsLotData) {
    return {
      ...base,
      total_lot: 0,
      score: resolveLeaderboardScore(contest, base, 0),
    };
  }

  const rangeEndIso = getContestRangeEndIso(contest);
  const startIso = contest.start_at;
  const filteredTrades = filterTradesInRange(tradeDocs, startIso, rangeEndIso);
  const totalLot = sumTotalLot(filteredTrades);

  if (filteredTrades.length === 0) {
    return {
      ...base,
      total_lot: totalLot,
      score: resolveLeaderboardScore(contest, base, totalLot),
    };
  }

  if (gainBasis === 'equity') {
    return {
      ...base,
      total_lot: totalLot,
      score: resolveLeaderboardScore(contest, base, totalLot),
    };
  }

  const startingBalance = Number(entry.starting_balance) || 0;
  const terminalBalance = Number(account.balance) || startingBalance;
  const { metrics } = deriveMetricsFromFirestoreTradeDocs(filteredTrades, terminalBalance);
  const contestScopedGain =
    startingBalance > 0
      ? Number(((metrics.profit / startingBalance) * 100).toFixed(2))
      : metrics.gain;

  const scoped = {
    ...base,
    gain: contestScopedGain,
    dd: metrics.dd,
    profit: metrics.profit,
    total_lot: totalLot,
  };

  return {
    ...scoped,
    score: resolveLeaderboardScore(contest, scoped, totalLot),
  };
}

async function loadFirestoreTradesForAccount(db, collections, account) {
  const userId = String(account.user_id || '');
  const accountKey = String(account.id || '');
  const metaapiCloudAccountId = String(account.metaapi_account_id || '');
  const login = account.login ? String(account.login) : '';

  const candidates = [
    ...new Set([accountKey, metaapiCloudAccountId, login].filter((value) => value.trim())),
  ];

  const byDocId = new Map();
  for (const accountId of candidates) {
    const snap = await db
      .collection(collections.metaApiTrades)
      .where('user_id', '==', userId)
      .where('account_id', '==', accountId)
      .get();
    for (const docSnap of snap.docs) {
      byDocId.set(docSnap.id, { id: docSnap.id, ...docSnap.data() });
    }
  }

  return Array.from(byDocId.values());
}

async function loadContestScopedMetricsForEntry(db, collections, { contest, account, entry }) {
  const tradeDocs = await loadFirestoreTradesForAccount(db, collections, account);
  return buildContestScopedMetrics(contest, account, entry, tradeDocs);
}

module.exports = {
  getContestRangeEndIso,
  filterTradesInRange,
  sumTotalLot,
  buildContestScopedMetrics,
  loadFirestoreTradesForAccount,
  loadContestScopedMetricsForEntry,
};
