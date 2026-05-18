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
 * MetaStats return-style ratios (gain, absoluteGain, dailyGain, monthlyGain).
 * Docs example: absoluteGain ~1.12 → 112% display. Live API often returns values already in % (e.g. -76.99).
 */
function ratioToPercentDisplay(value) {
  if (value === null || value === undefined) return null;
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  if (Math.abs(n) <= 2 && n !== 0) return Number((n * 100).toFixed(2));
  return Number(n.toFixed(2));
}

/** API body is `{ metrics: { ... } }` (200) or flat metrics on 202 poll payloads. */
function unwrapMetaStatsMetricsBody(body) {
  if (!body || typeof body !== 'object') return null;
  if (body.metrics && typeof body.metrics === 'object') return body.metrics;
  return body;
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

  const mapped = {
    gain: ratioToPercentDisplay(raw.gain),
    metaapi_abs_gain: ratioToPercentDisplay(raw.absoluteGain),
    metaapi_daily_gain: ratioToPercentDisplay(raw.dailyGain),
    metaapi_monthly_gain: ratioToPercentDisplay(raw.monthlyGain),
    dd: resolveMaxDrawdownPercent(raw),
    profit: coerceNumber(raw.profit),
    balance: coerceNumber(raw.balance),
    equity: coerceNumber(raw.equity),
    metaapi_highest_balance: coerceNumber(raw.highestBalance),
    metaapi_highest_balance_date:
      typeof raw.highestBalanceDate === 'string' ? raw.highestBalanceDate : null,
    metaapi_interest: coerceNumber(raw.interest),
    metaapi_deposits: coerceNumber(raw.deposits),
    metaapi_withdrawals: coerceNumber(raw.withdrawals),
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
  mapMetaStatsToAccountMetrics,
  fetchMetaStatsMetrics,
};
