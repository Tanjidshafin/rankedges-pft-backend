/**
 * Contest leaderboard metrics: MetaStats gain + optional contest-window lot totals.
 */

const { resolveGainBasis } = require('./contestGainMetrics');
const { buildContestLeaderboardMetricsFromAccount } = require('./contestMetaStatsGain');
const { resolveLeaderboardScore } = require('./contestRanking');
const {
  filterDealsForMetrics,
  metaApiDealToTradeSnapshot,
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

function sumLotsFromMetaApiDeals(rawDeals, platform) {
  if (!Array.isArray(rawDeals) || rawDeals.length === 0) return 0;
  const metricDeals = filterDealsForMetrics(rawDeals, platform);
  return sumTotalLot(metricDeals.map((deal) => metaApiDealToTradeSnapshot(deal)));
}

function contestNeedsLotTotals(contest) {
  const gainBasis = resolveGainBasis(contest);
  return contest.type === 'standard' || gainBasis === 'balance';
}

function resolveContestWindowLots(contest, tradeDocs) {
  if (!contestNeedsLotTotals(contest)) return 0;
  const rangeEndIso = getContestRangeEndIso(contest);
  const filteredTrades = filterTradesInRange(tradeDocs, contest.start_at, rangeEndIso);
  return sumTotalLot(filteredTrades);
}

function finalizeContestMetrics(contest, account, entry, totalLot, options = {}) {
  const built = buildContestLeaderboardMetricsFromAccount(contest, account, {
    totalLot,
    entry,
    requireSyncedAt: options.requireSyncedAt,
  });
  if (!built.ok) {
    return built;
  }
  return {
    ok: true,
    metrics: {
      ...built.metrics,
      score: resolveLeaderboardScore(contest, built.metrics, totalLot),
    },
  };
}

/**
 * Metrics from persisted Firestore account + optional contest-window lots from trade docs.
 */
function buildContestScopedMetrics(contest, account, entry, tradeDocs) {
  const totalLot = resolveContestWindowLots(contest, tradeDocs);
  return finalizeContestMetrics(contest, account, entry, totalLot);
}

/**
 * Metrics from live MetaStats account snapshot + optional MetaApi deals for contest-window lots.
 */
function buildContestScopedMetricsFromMetaApi(contest, liveAccount, entry, rawDeals, platform) {
  const totalLot = contestNeedsLotTotals(contest)
    ? sumLotsFromMetaApiDeals(rawDeals, platform)
    : 0;
  return finalizeContestMetrics(contest, liveAccount, entry, totalLot, { requireSyncedAt: false });
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
  contestNeedsLotTotals,
  buildContestScopedMetrics,
  buildContestScopedMetricsFromMetaApi,
  loadFirestoreTradesForAccount,
  loadContestScopedMetricsForEntry,
};
