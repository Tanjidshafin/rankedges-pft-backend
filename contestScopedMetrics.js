/**
 * Contest-window metrics from persisted Firestore trades (server-side).
 */

const {
  buildLeaderboardMetricUpdate,
  resolveGainBasis,
  sanitizeContestGainPercent,
  resolveContestGainBaseline,
  contestGainPercentFromTradeMetrics,
} = require('./contestGainMetrics');
const { resolveLeaderboardScore } = require('./contestRanking');
const {
  deriveMetricsFromFirestoreTradeDocs,
  deriveSyncedMetricsPackage,
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

function entryFieldsFromLeaderboard(entry) {
  return {
    starting_balance: entry.starting_balance,
    starting_equity: entry.starting_equity,
    peak_equity: entry.peak_equity,
    lowest_equity: entry.lowest_equity,
  };
}

/**
 * Contest metrics using live MetaStats/MetaApi deal history (not Firestore trades).
 * @param {object} contest
 * @param {{ balance: number, equity: number, gain?: number, dd?: number, profit?: number }} liveAccount
 * @param {object} entry leaderboard row
 * @param {object[]} rawDeals MetaApi history deals in contest window (may be empty)
 * @param {'mt4'|'mt5'} platform
 */
function buildBalanceBasisContestGainFromTrades(metricsPackage, entry, terminalValue) {
  const resolvedBaseline = resolveContestGainBaseline(
    entry.starting_balance,
    metricsPackage.syntheticStart,
    terminalValue,
  );
  return {
    gain: contestGainPercentFromTradeMetrics(metricsPackage.metrics, resolvedBaseline),
    resolvedBaseline,
  };
}

function buildContestScopedMetricsFromMetaApi(contest, liveAccount, entry, rawDeals, platform) {
  const gainBasis = resolveGainBasis(contest);
  const needsLotData = contest.type === 'standard' || gainBasis === 'balance';
  const fields = entryFieldsFromLeaderboard(entry);
  const deals = Array.isArray(rawDeals) ? rawDeals : [];
  const totalLot = needsLotData ? sumLotsFromMetaApiDeals(deals, platform) : 0;

  if (!needsLotData) {
    const base = buildLeaderboardMetricUpdate({ contest, account: liveAccount, entry: fields });
    return {
      ...base,
      total_lot: 0,
      score: resolveLeaderboardScore(contest, base, 0),
    };
  }

  if (gainBasis === 'equity') {
    const terminalEquity = Number(liveAccount.equity) || Number(liveAccount.balance) || 0;
    const metricsPackage = deriveSyncedMetricsPackage(terminalEquity, deals, platform);
    const resolvedEquityBaseline = resolveContestGainBaseline(
      entry.starting_equity ?? entry.starting_balance,
      metricsPackage.syntheticStart,
      terminalEquity,
    );
    const repairedFields = {
      ...fields,
      ...(resolvedEquityBaseline > 0
        ? { starting_equity: resolvedEquityBaseline, starting_balance: resolvedEquityBaseline }
        : {}),
    };
    const base = buildLeaderboardMetricUpdate({ contest, account: liveAccount, entry: repairedFields });
    return {
      ...base,
      total_lot: totalLot,
      score: resolveLeaderboardScore(contest, base, totalLot),
      resolved_baseline: resolvedEquityBaseline > 0 ? resolvedEquityBaseline : undefined,
    };
  }

  const terminalBalance = Number(liveAccount.balance) || Number(entry.starting_balance) || 0;
  const metricsPackage = deriveSyncedMetricsPackage(terminalBalance, deals, platform);
  const { gain: contestScopedGain, resolvedBaseline } = buildBalanceBasisContestGainFromTrades(
    metricsPackage,
    entry,
    terminalBalance,
  );

  const scoped = buildLeaderboardMetricUpdate({
    contest,
    account: liveAccount,
    entry: fields,
    contestScopedGain,
    contestScopedProfit: metricsPackage.metrics.profit,
    contestScopedDd: metricsPackage.metrics.dd,
  });

  return {
    ...scoped,
    total_lot: totalLot,
    score: resolveLeaderboardScore(contest, scoped, totalLot),
    resolved_baseline: resolvedBaseline > 0 ? resolvedBaseline : undefined,
  };
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

  const terminalBalance = Number(account.balance) || Number(entry.starting_balance) || 0;
  const metricsPackage = deriveMetricsFromFirestoreTradeDocs(filteredTrades, terminalBalance);
  const { gain: contestScopedGain, resolvedBaseline } = buildBalanceBasisContestGainFromTrades(
    metricsPackage,
    entry,
    terminalBalance,
  );

  const scoped = {
    ...base,
    gain: contestScopedGain,
    dd: metricsPackage.metrics.dd,
    profit: metricsPackage.metrics.profit,
    total_lot: totalLot,
    resolved_baseline: resolvedBaseline > 0 ? resolvedBaseline : undefined,
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
  buildContestScopedMetricsFromMetaApi,
  loadFirestoreTradesForAccount,
  loadContestScopedMetricsForEntry,
};
