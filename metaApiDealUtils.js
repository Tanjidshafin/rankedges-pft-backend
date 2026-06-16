/**
 * Mirrors src/services/metaApiDealNormalization + metrics derivation for server-side MetaApi sync.
 */
const { formatMetaApiHttpError } = require('./metaApiHttpErrors');
const HISTORY_DEALS_PAGE_LIMIT = 1000;

const MT5_CLOSE_ENTRIES = new Set(['DEAL_ENTRY_OUT', 'DEAL_ENTRY_INOUT', 'DEAL_ENTRY_OUT_BY']);

const BALANCE_ADJUST_DEAL_TYPES = new Set([
  'DEAL_TYPE_BALANCE',
  'DEAL_TYPE_CREDIT',
  'DEAL_TYPE_CORRECTION',
  'DEAL_TYPE_BONUS',
]);

function normalizeDeal(deal) {
  return {
    id: String(deal.id),
    symbol: deal.symbol || '',
    type: deal.type,
    volume: Number(deal.volume || 0),
    price: Number(deal.price || 0),
    profit: Number(deal.profit || 0),
    time: deal.time,
    swap: Number(deal.swap || 0),
    commission: Number(deal.commission || 0),
    comment: deal.comment,
    entryType: deal.entryType,
    positionId: deal.positionId,
    platform: deal.platform,
  };
}

function isTradingBuySell(type) {
  return type === 'DEAL_TYPE_BUY' || type === 'DEAL_TYPE_SELL';
}

function filterDealsForMetrics(deals, platform) {
  return deals.filter((d) => {
    if (!isTradingBuySell(d.type)) return false;
    const plat = platform === 'mt4' ? 'mt4' : 'mt5';
    if (plat === 'mt5') {
      if (!d.entryType) return true;
      return MT5_CLOSE_ENTRIES.has(d.entryType);
    }
    if (d.entryType) return MT5_CLOSE_ENTRIES.has(d.entryType);
    return true;
  });
}

function getDealBalanceImpact(deal) {
  return Number((deal.profit || 0) + (deal.swap || 0) + (deal.commission || 0));
}

function sumBalanceAdjustmentsInWindow(rawDeals) {
  return rawDeals
    .filter((d) => d.type && BALANCE_ADJUST_DEAL_TYPES.has(d.type))
    .reduce((sum, d) => sum + getDealBalanceImpact(d), 0);
}

function tradeSnapshotNet(trade) {
  return Number((trade.profit || 0) + (trade.swap || 0) + (trade.commission || 0));
}

function metaApiDealToTradeSnapshot(deal) {
  const t = deal.time != null && deal.time !== '' ? deal.time : null;
  return {
    id: deal.id,
    symbol: deal.symbol || '',
    type: deal.type,
    volume: deal.volume,
    openPrice: deal.price,
    closePrice: deal.price,
    profit: deal.profit,
    openTime: t,
    closeTime: t,
    swap: deal.swap,
    commission: deal.commission,
    comment: deal.comment == null ? null : deal.comment,
  };
}

function tradeSortTimeMs(trade) {
  const raw = trade.closeTime || trade.openTime;
  if (raw == null || raw === '') return 0;
  const ms = new Date(raw).getTime();
  return Number.isFinite(ms) ? ms : 0;
}

function calculateMetrics(trades, initialBalance) {
  const sortedTrades = [...trades].sort((left, right) => {
    return tradeSortTimeMs(left) - tradeSortTimeMs(right);
  });

  let wins = 0;
  let losses = 0;
  let totalProfit = 0;
  let maxDrawdown = 0;
  let peakBalance = initialBalance;
  let currentBalance = initialBalance;

  for (const trade of sortedTrades) {
    const netRow = tradeSnapshotNet(trade);
    totalProfit += netRow;
    currentBalance += netRow;
    if (netRow > 0) wins += 1;
    else if (netRow < 0) losses += 1;
    if (currentBalance > peakBalance) peakBalance = currentBalance;
    const drawdown = ((peakBalance - currentBalance) / peakBalance) * 100;
    if (drawdown > maxDrawdown) maxDrawdown = drawdown;
  }

  const totalTrades = wins + losses;
  const winRate = totalTrades > 0 ? (wins / totalTrades) * 100 : 0;
  const gain = initialBalance > 0 ? (totalProfit / initialBalance) * 100 : 0;

  return {
    gain: Number(gain.toFixed(2)),
    dd: Number(maxDrawdown.toFixed(2)),
    profit: Number(totalProfit.toFixed(2)),
    win_rate: Number(winRate.toFixed(1)),
    total_trades: totalTrades,
  };
}

function deriveSyncedMetricsPackage(terminalBalance, rawDeals, platform) {
  const metricDeals = filterDealsForMetrics(rawDeals, platform);
  const normalizedTrades = metricDeals.map(metaApiDealToTradeSnapshot);
  const adjustments = sumBalanceAdjustmentsInWindow(rawDeals);
  const tradingNetPeriod = metricDeals.reduce((sum, d) => sum + getDealBalanceImpact(d), 0);

  let syntheticStart = terminalBalance - tradingNetPeriod - adjustments;
  if (!Number.isFinite(syntheticStart) || syntheticStart <= 0) {
    syntheticStart = Math.abs(terminalBalance) > 0 ? Number(terminalBalance) : Number.EPSILON;
  }

  const metrics = calculateMetrics(normalizedTrades, syntheticStart);
  return { normalizedTrades, metrics, syntheticStart };
}

async function fetchMetaApiHistoryDealsPaginated(
  clientApiUrl,
  accountId,
  authToken,
  startIso,
  endIsoExclusive,
  onProgress,
) {
  const encodedStart = encodeURIComponent(startIso);
  const encodedEnd = encodeURIComponent(endIsoExclusive);
  const byId = new Map();
  let offset = 0;

  while (true) {
    if (typeof onProgress === 'function') {
      await onProgress({ offset, loaded: byId.size });
    }
    const url = `${clientApiUrl}/users/current/accounts/${accountId}/history-deals/time/${encodedStart}/${encodedEnd}?offset=${offset}&limit=${HISTORY_DEALS_PAGE_LIMIT}`;
    const response = await fetch(url, {
      headers: {
        'auth-token': authToken,
        'Content-Type': 'application/json',
      },
    });
    if (!response.ok) {
      throw new Error(await formatMetaApiHttpError('history-deals', response, { accountId }));
    }
    const batch = await response.json();
    const rows = Array.isArray(batch) ? batch : [];
    for (const row of rows) {
      const mapped = normalizeDeal(row);
      byId.set(mapped.id, mapped);
    }
    if (typeof onProgress === 'function') {
      await onProgress({ offset, loaded: byId.size, pageRows: rows.length });
    }
    if (rows.length < HISTORY_DEALS_PAGE_LIMIT) break;
    offset += HISTORY_DEALS_PAGE_LIMIT;
  }

  return Array.from(byId.values());
}

const FULL_HISTORY_START_ISO = '2000-01-01T00:00:00.000Z';

async function fetchMetaApiHistoryDealsFullRange(clientApiUrl, accountId, authToken, onProgress) {
  const endIso = new Date().toISOString();
  return fetchMetaApiHistoryDealsPaginated(
    clientApiUrl,
    accountId,
    authToken,
    FULL_HISTORY_START_ISO,
    endIso,
    onProgress,
  );
}

function firestoreTradeDocToSnapshot(data) {
  return {
    id: String(data.id || ''),
    symbol: data.symbol || '',
    type: data.type,
    volume: Number(data.volume || 0),
    openPrice: Number(data.openPrice || 0),
    closePrice: Number(data.closePrice || 0),
    profit: Number(data.profit || 0),
    openTime: data.openTime ?? null,
    closeTime: data.closeTime ?? null,
    swap: Number(data.swap || 0),
    commission: Number(data.commission || 0),
    comment: data.comment == null ? null : data.comment,
  };
}

/**
 * Derive headline activity metrics from persisted metaApiTrades rows (no MetaApi fetch).
 * Uses synthetic start (terminal balance minus trade impacts), same as deriveSyncedMetricsPackage.
 * @param {object[]} tradeDocs plain Firestore trade payloads
 * @param {number} terminalBalance live or MetaStats balance for gain/dd baseline
 */
function deriveMetricsFromFirestoreTradeDocs(tradeDocs, terminalBalance) {
  const normalizedTrades = (Array.isArray(tradeDocs) ? tradeDocs : []).map((row) =>
    firestoreTradeDocToSnapshot(row),
  );
  const tradingNetPeriod = normalizedTrades.reduce((sum, trade) => sum + tradeSnapshotNet(trade), 0);
  const terminal = Number(terminalBalance);
  let syntheticStart = Number.isFinite(terminal) ? terminal - tradingNetPeriod : 0;
  if (!Number.isFinite(syntheticStart) || syntheticStart <= 0) {
    syntheticStart = Number.isFinite(terminal) && terminal > 0 ? terminal : 0;
  }

  const metrics = calculateMetrics(normalizedTrades, syntheticStart > 0 ? syntheticStart : 1);
  return { normalizedTrades, metrics, syntheticStart: syntheticStart > 0 ? syntheticStart : 0 };
}

module.exports = {
  HISTORY_DEALS_PAGE_LIMIT,
  FULL_HISTORY_START_ISO,
  fetchMetaApiHistoryDealsPaginated,
  fetchMetaApiHistoryDealsFullRange,
  filterDealsForMetrics,
  deriveSyncedMetricsPackage,
  deriveMetricsFromFirestoreTradeDocs,
  firestoreTradeDocToSnapshot,
  calculateMetrics,
  metaApiDealToTradeSnapshot,
};
