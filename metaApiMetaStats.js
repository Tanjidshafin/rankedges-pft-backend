/**
 * MetaStats regional metrics API client (gain/profit/dd from authoritative history).
 */

const LOG_CAP = 8000;

class MetaStatsFetchError extends Error {
  /**
   * @param {number} status HTTP status code
   * @param {string} region metastats region slug
   * @param {string} bodyText raw response body (may be truncated in message)
   */
  constructor(status, region, bodyText) {
    const safeRegion = region || '?';
    const snippet = typeof bodyText === 'string' ? bodyText.slice(0, 2000) : '';
    super(`MetaStats metrics HTTP ${status} (${safeRegion}) ${snippet}`);
    this.name = 'MetaStatsFetchError';
    /** @type {number} */
    this.status = status;
    /** @type {string} */
    this.region = safeRegion;
    /** @type {string} */
    this.bodyText = typeof bodyText === 'string' ? bodyText : '';
  }
}

function safeJsonSnippet(payload) {
  try {
    const s = typeof payload === 'string' ? payload : JSON.stringify(payload);
    return s.length > LOG_CAP ? `${s.slice(0, LOG_CAP)}…[truncated]` : s;
  } catch {
    return '[unserializable]';
  }
}

function parseRetryAfterSeconds(response) {
  const header = response.headers?.get?.('retry-after');
  if (!header) return undefined;
  const n = Number(header);
  if (Number.isFinite(n) && n >= 0) return Math.min(120, n);
  const when = Date.parse(header);
  if (!Number.isNaN(when)) {
    const waitMs = Math.max(0, when - Date.now());
    return Math.min(120, Math.ceil(waitMs / 1000));
  }
  return undefined;
}

function getMetaStatsApiUrl(region) {
  const slug = String(region || 'new-york').trim().toLowerCase() || 'new-york';
  return `https://metastats-api-v1.${slug}.agiliumtrade.ai`;
}

/**
 * MetaStats compound daily/monthly rate of return (dailyGain, monthlyGain, dailyGrowth gains).
 * Docs: decimal rate where 0.023 → 2.3%. Live API may also send values already in % (e.g. 12.12).
 */
function compoundRateToPercent(value, fractionDigits = 2) {
  if (value === null || value === undefined) return null;
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  if (n === 0) return 0;

  const abs = Math.abs(n);
  let result;
  if (abs < 1) {
    result = n * 100;
  } else if (abs >= 2) {
    result = n;
  } else {
    console.warn(
      '[MetaStats][compoundRateToPercent] value in 1..2 range treated as multiplier offset',
      { value: n },
    );
    result = n >= 0 ? (n - 1) * 100 : (n + 1) * 100;
  }
  return Number(result.toFixed(fractionDigits));
}

/**
 * dailyGain can arrive in a different scale than gain/monthlyGain/absoluteGain on the same payload.
 * When headline gain fields cluster around monthlyGain (percent mode) but dailyGain sits in 1..2
 * and would have been inflated by legacy ratio*100, align daily with monthly for short-history accounts.
 */
function resolveDailyGainPercent(raw, fractionDigits = 2) {
  const dailyMapped = compoundRateToPercent(raw.dailyGain, fractionDigits);
  const monthly = Number(raw.monthlyGain);
  const gain = Number(raw.gain);
  const absGain = Number(raw.absoluteGain);
  const dailyRaw = Number(raw.dailyGain);
  const days = Number(raw.daysSinceTradingStarted);

  if (!Number.isFinite(dailyRaw) || !Number.isFinite(monthly) || Math.abs(monthly) < 2) {
    return dailyMapped;
  }
  if (Math.abs(dailyRaw) < 1 || Math.abs(dailyRaw) >= 2) {
    return dailyMapped;
  }

  const clustered =
    [monthly, gain, absGain].filter(Number.isFinite).length >= 2 &&
    [gain, absGain]
      .filter(Number.isFinite)
      .every((v) => Math.abs(v - monthly) < 0.5);
  const shortHistory = Number.isFinite(days) && days < 1;
  const legacyInflated = Math.abs(dailyRaw * 100) > Math.abs(monthly) * 2;

  if (clustered && legacyInflated && shortHistory) {
    console.warn('[MetaStats][dailyGain] reconciled with monthlyGain for short-history account', {
      dailyGain: dailyRaw,
      monthlyGain: monthly,
      daysSinceTradingStarted: days,
    });
    return compoundRateToPercent(monthly, fractionDigits);
  }

  return dailyMapped;
}

/**
 * MetaStats gain / absoluteGain multiplier-style ratios.
 * Fallback when deposits are unavailable — prefer deriveGainPercentFromDeposits in mapMetaStatsToAccountMetrics.
 */
function gainMultiplierToPercent(value, fractionDigits = 2) {
  if (value === null || value === undefined) return null;
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  if (n === 0) return 0;

  const abs = Math.abs(n);
  let result;
  if (abs < 1) {
    result = n * 100;
  } else if (abs >= 2) {
    result = n;
  } else {
    result = n >= 0 ? (n - 1) * 100 : (n + 1) * 100;
  }
  return Number(result.toFixed(fractionDigits));
}

function deriveGainPercentFromDeposits(profit, deposits, withdrawals = 0) {
  const netDeposits = Number(deposits) - Number(withdrawals || 0);
  if (!Number.isFinite(Number(profit)) || !Number.isFinite(netDeposits) || netDeposits <= 0) {
    return null;
  }
  return Number(((Number(profit) / netDeposits) * 100).toFixed(2));
}

function deriveAbsoluteGainPercent(balance, deposits, withdrawals = 0) {
  const netDeposits = Number(deposits) - Number(withdrawals || 0);
  if (!Number.isFinite(Number(balance)) || !Number.isFinite(netDeposits) || netDeposits <= 0) {
    return null;
  }
  return Number((((Number(balance) - netDeposits) / netDeposits) * 100).toFixed(2));
}

function resolveHeadlineGainPercent(rawGain, profit, deposits, withdrawals) {
  const fromDeposits = deriveGainPercentFromDeposits(profit, deposits, withdrawals);
  const fromApi = gainMultiplierToPercent(rawGain);

  if (fromDeposits != null) {
    if (
      fromApi != null &&
      fromDeposits !== 0 &&
      (Math.abs(fromApi / fromDeposits) > 5 || Math.abs(fromApi - fromDeposits) > Math.max(2, Math.abs(fromDeposits) * 2))
    ) {
      console.warn('[MetaStats][gain] using deposit-derived gain; API mapping diverged', {
        fromDeposits,
        fromApi,
        profit,
        deposits,
        rawGain,
      });
    }
    return fromDeposits;
  }

  return fromApi;
}

function resolveAbsoluteGainPercent(rawAbsGain, balance, profit, deposits, withdrawals) {
  const fromBalance = deriveAbsoluteGainPercent(balance, deposits, withdrawals);
  if (fromBalance != null) return fromBalance;

  const fromProfit = deriveGainPercentFromDeposits(profit, deposits, withdrawals);
  if (fromProfit != null) return fromProfit;

  return gainMultiplierToPercent(rawAbsGain);
}

/** @deprecated Use compoundRateToPercent or gainMultiplierToPercent */
function ratioToPercentDisplay(value) {
  return gainMultiplierToPercent(value, 2);
}

/** API body is `{ metrics: { ... } }` (200) or flat metrics on 202 poll payloads. */
function unwrapMetaStatsMetricsBody(body) {
  if (!body || typeof body !== 'object') return null;
  if (body.metrics && typeof body.metrics === 'object') return body.metrics;
  return body;
}

const DEFAULT_DAILY_GROWTH_MAX_POINTS = 2000;

function percentForChart(value) {
  return compoundRateToPercent(value, 4);
}

/**
 * Downsample series evenly while keeping first and last points.
 * @param {unknown[]} rows
 * @param {number} maxPoints
 */
function downsampleSeries(rows, maxPoints) {
  if (!Array.isArray(rows) || rows.length <= maxPoints) return rows || [];
  if (maxPoints < 2) return [rows[0], rows[rows.length - 1]].filter(Boolean);
  const out = [];
  const lastIndex = rows.length - 1;
  for (let i = 0; i < maxPoints; i += 1) {
    const idx = Math.round((i / (maxPoints - 1)) * lastIndex);
    out.push(rows[idx]);
  }
  return out;
}

/**
 * MetaStats dailyGrowth → Firestore-safe chart series (Myfxbook-style tabs).
 * @param {unknown} dailyGrowth
 * @param {{ terminalBalance?: number, terminalEquity?: number, maxPoints?: number }} [opts]
 */
function normalizeDailyGrowthSeries(dailyGrowth, opts = {}) {
  if (!Array.isArray(dailyGrowth) || dailyGrowth.length === 0) return [];

  const terminalBalance = Number(opts.terminalBalance);
  const terminalEquity = Number(opts.terminalEquity);
  const equityRatio =
    Number.isFinite(terminalBalance) && terminalBalance > 0 && Number.isFinite(terminalEquity)
      ? terminalEquity / terminalBalance
      : null;

  const sorted = [...dailyGrowth]
    .filter((row) => row && typeof row === 'object' && typeof row.date === 'string')
    .sort((a, b) => String(a.date).localeCompare(String(b.date)));

  const mapped = sorted.map((row) => {
    const balance = coerceNumber(row.balance) ?? 0;
    const point = {
      date: String(row.date).slice(0, 10),
      balance,
      totalProfit: coerceNumber(row.totalProfit) ?? 0,
      totalGains: percentForChart(row.totalGains) ?? 0,
    };
    const gains = percentForChart(row.gains);
    if (gains != null) point.gains = gains;
    const drawdownPercentage = percentForChart(row.drawdownPercentage);
    if (drawdownPercentage != null) point.drawdownPercentage = drawdownPercentage;
    if (equityRatio != null && balance > 0) {
      point.equityEstimate = Number((balance * equityRatio).toFixed(2));
    }
    return point;
  });

  const maxPoints = Math.max(
    50,
    Math.min(Number(opts.maxPoints || process.env.METASTATS_DAILY_GROWTH_MAX_POINTS) || DEFAULT_DAILY_GROWTH_MAX_POINTS, 5000),
  );
  const downsampled = downsampleSeries(mapped, maxPoints);
  return sanitizeDailyGrowthSeriesForFirestore(downsampled);
}

/**
 * Strip undefined from a single daily-growth point (Firestore-safe).
 * @param {Record<string, unknown>} point
 */
function sanitizeDailyGrowthPoint(point) {
  const out = {
    date: String(point.date),
    balance: Number(point.balance) || 0,
    totalProfit: Number(point.totalProfit) || 0,
    totalGains: Number(point.totalGains) || 0,
  };
  const gains = point.gains;
  if (gains !== undefined && gains !== null && Number.isFinite(Number(gains))) {
    out.gains = Number(gains);
  }
  const dd = point.drawdownPercentage;
  if (dd !== undefined && dd !== null && Number.isFinite(Number(dd))) {
    out.drawdownPercentage = Number(dd);
  }
  const equity = point.equityEstimate;
  if (equity !== undefined && equity !== null && Number.isFinite(Number(equity))) {
    out.equityEstimate = Number(equity);
  }
  return out;
}

/** @param {unknown[]} series */
function sanitizeDailyGrowthSeriesForFirestore(series) {
  if (!Array.isArray(series)) return [];
  return series.map((row) =>
    row && typeof row === 'object' ? sanitizeDailyGrowthPoint(row) : sanitizeDailyGrowthPoint({}),
  );
}

/** Omit huge nested arrays before Firestore snapshot persist. */
function slimMetaStatsForStorage(body) {
  if (!body || typeof body !== 'object') return body;
  const metrics = unwrapMetaStatsMetricsBody(body);
  if (!metrics || typeof metrics !== 'object') return body;
  const { currencySummary, dailyGrowth, ...headline } = metrics;
  return {
    metrics: headline,
    _trimmed: {
      currencySummarySymbols: Array.isArray(currencySummary) ? currencySummary.length : 0,
      dailyGrowthDays: Array.isArray(dailyGrowth) ? dailyGrowth.length : 0,
    },
  };
}

function resolveMaxDrawdownPercent(metrics) {
  if (!metrics || typeof metrics !== 'object') return null;
  const direct = [
    metrics.maxDrawdown,
    metrics.maxDrawdownPercentage,
    metrics.relativeDrawdown,
    metrics.drawdown,
  ];
  for (const candidate of direct) {
    const dd = maxDrawdownToDisplayPercent(candidate);
    if (dd != null) return dd;
  }
  const growth = metrics.dailyGrowth;
  if (!Array.isArray(growth)) return null;
  let peak = 0;
  for (const row of growth) {
    const d = Number(row?.drawdownPercentage);
    if (Number.isFinite(d) && d > peak) peak = d;
  }
  return peak > 0 ? Number(peak.toFixed(2)) : null;
}

/**
 * Already a UI percentage field (wonTradesPercent is 66.66…).
 */
function percentAlreadyDisplay(value, fractionDigits = 2) {
  if (value === null || value === undefined) return null;
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  const d = fractionDigits ?? 2;
  return Number(n.toFixed(d));
}

/** maxDrawdown: fraction (e.g. 0.083) or already percent — normalize to UI percent number. */
function maxDrawdownToDisplayPercent(value) {
  if (value === null || value === undefined) return null;
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  if (Math.abs(n) <= 1) return Number((n * 100).toFixed(2));
  return Number(n.toFixed(2));
}

function coerceNumber(value) {
  if (value === null || value === undefined) return null;
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  return n;
}

function coerceInt(value) {
  if (value === null || value === undefined) return null;
  const n = Math.trunc(Number(value));
  if (!Number.isFinite(n)) return null;
  return n;
}

function resolveTotalTradesFromMetaStats(raw) {
  const direct = coerceInt(raw.trades);
  if (direct != null && direct > 0) return direct;
  const totalTrades = coerceInt(raw.totalTrades);
  if (totalTrades != null && totalTrades > 0) return totalTrades;
  const won = coerceInt(raw.wonTrades);
  const lost = coerceInt(raw.lostTrades);
  if (won != null && lost != null) return won + lost;
  if (direct != null) return direct;
  if (totalTrades != null) return totalTrades;
  return direct;
}

/** True when MetaStats reports no closed-trade activity (balance-only snapshot). */
function isMetaStatsActivityEmpty(mapped) {
  const trades = mapped.total_trades ?? 0;
  if (trades > 0) return false;
  const profit = mapped.profit ?? 0;
  const gain = mapped.gain ?? 0;
  const winRate = mapped.win_rate ?? 0;
  const dd = mapped.dd ?? 0;
  return profit === 0 && gain === 0 && winRate === 0 && dd === 0;
}

function mergeActivityMetricsInto(mapped, derived) {
  if (!derived || typeof derived !== 'object') return mapped;
  mapped.gain = derived.gain;
  mapped.dd = derived.dd;
  mapped.profit = derived.profit;
  mapped.win_rate = derived.win_rate;
  mapped.total_trades = derived.total_trades;
  return mapped;
}

function mapMetaStatsToAccountMetrics(body) {
  const raw = unwrapMetaStatsMetricsBody(body);
  if (!raw || typeof raw !== 'object') {
    throw new Error('MetaStats metrics payload is missing or invalid');
  }

  const totalTrades = resolveTotalTradesFromMetaStats(raw);
  if ((totalTrades ?? 0) === 0) {
    console.log('[MetaStats][empty-activity-fields]', safeJsonSnippet({
      trades: raw.trades,
      totalTrades: raw.totalTrades,
      wonTrades: raw.wonTrades,
      lostTrades: raw.lostTrades,
      profit: raw.profit,
      gain: raw.gain,
    }));
  }

  const profit = coerceNumber(raw.profit);
  const deposits = coerceNumber(raw.deposits);
  const withdrawals = coerceNumber(raw.withdrawals);
  const balance = coerceNumber(raw.balance);

  const mapped = {
    gain: resolveHeadlineGainPercent(raw.gain, profit, deposits, withdrawals),
    metaapi_abs_gain: resolveAbsoluteGainPercent(
      raw.absoluteGain,
      balance,
      profit,
      deposits,
      withdrawals,
    ),
    metaapi_daily_gain: resolveDailyGainPercent(raw),
    metaapi_monthly_gain: compoundRateToPercent(raw.monthlyGain),
    dd: resolveMaxDrawdownPercent(raw),
    profit,
    balance: balance,
    equity: coerceNumber(raw.equity),
    metaapi_highest_balance: coerceNumber(raw.highestBalance),
    metaapi_highest_balance_date:
      typeof raw.highestBalanceDate === 'string' ? raw.highestBalanceDate : null,
    metaapi_interest: coerceNumber(raw.interest),
    metaapi_deposits: deposits,
    metaapi_withdrawals: withdrawals,
    win_rate: percentAlreadyDisplay(raw.wonTradesPercent, 2),
    total_trades: totalTrades,
  };

  console.log('[MetaStats][mapped]', safeJsonSnippet(mapped));
  return mapped;
}

/**
 * @param {string} metaApiAccountId provisioning UUID
 * @param {string} token auth-token (workspace)
 * @param {string} region e.g. new-york
 * @param {{ includeOpenPositions?: boolean }} opts
 */
async function fetchMetaStatsMetrics(metaApiAccountId, token, region, opts = {}) {
  const base = getMetaStatsApiUrl(region);
  const qp = opts.includeOpenPositions === false ? '' : '?includeOpenPositions=true';
  const url = `${base}/users/current/accounts/${encodeURIComponent(metaApiAccountId)}/metrics${qp}`;

  const started = Date.now();
  const maxMs = Number(process.env.METASTATS_POLL_MAX_MS || 180 * 1000);
  let attempt = 0;

  while (Date.now() - started < maxMs) {
    const response = await fetch(url, {
      headers: {
        'auth-token': token,
        'Content-Type': 'application/json',
      },
    });

    const cloned = response.clone();
    let bodySnippet;
    try {
      const text = await cloned.text();
      bodySnippet = text;
    } catch {
      bodySnippet = '[read failed]';
    }

    if (response.status === 202) {
      console.log('[MetaStats][raw]', `status=${response.status}`, safeJsonSnippet(bodySnippet));
      const secs =
        parseRetryAfterSeconds(response) ?? Math.min(20, Math.max(2, 2 ** Math.min(attempt, 5)));
      attempt += 1;
      await new Promise((r) => setTimeout(r, secs * 1000));
      continue;
    }

    if (!response.ok) {
      console.log('[MetaStats][raw]', `status=${response.status}`, safeJsonSnippet(bodySnippet));
      throw new MetaStatsFetchError(response.status, region, bodySnippet || '');
    }

    let json;
    try {
      json = JSON.parse(bodySnippet);
    } catch (e) {
      throw new Error(`MetaStats metrics: invalid JSON body (${String(e)})`);
    }

    console.log('[MetaStats][raw]', `status=${response.status}`, safeJsonSnippet(json));
    return json;
  }

  throw new Error(`MetaStats metrics timed out after ${Math.round(maxMs / 1000)}s (${region}).`);
}

module.exports = {
  LOG_CAP,
  MetaStatsFetchError,
  safeJsonSnippet,
  getMetaStatsApiUrl,
  compoundRateToPercent,
  gainMultiplierToPercent,
  deriveGainPercentFromDeposits,
  deriveAbsoluteGainPercent,
  resolveHeadlineGainPercent,
  resolveAbsoluteGainPercent,
  resolveDailyGainPercent,
  ratioToPercentDisplay,
  /** @deprecated alias — plan name */
  ratioToPercent: ratioToPercentDisplay,
  unwrapMetaStatsMetricsBody,
  slimMetaStatsForStorage,
  resolveMaxDrawdownPercent,
  maxDrawdownToDisplayPercent,
  resolveTotalTradesFromMetaStats,
  isMetaStatsActivityEmpty,
  mergeActivityMetricsInto,
  normalizeDailyGrowthSeries,
  sanitizeDailyGrowthSeriesForFirestore,
  sanitizeDailyGrowthPoint,
  downsampleSeries,
  mapMetaStatsToAccountMetrics,
  fetchMetaStatsMetrics,
};
