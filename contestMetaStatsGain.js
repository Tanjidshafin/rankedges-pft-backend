/**
 * Contest gain from MetaStats-synced account fields (same methodology as Admin accounts table).
 */

const {
  resolveGainBasis,
  sanitizeContestGainPercent,
  MIN_CONTEST_BASELINE,
} = require('./contestGainMetrics');

function asFiniteNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function resolveNetDeposits(account) {
  const deposits = asFiniteNumber(account.metaapi_deposits, 0);
  const withdrawals = asFiniteNumber(account.metaapi_withdrawals, 0);
  return deposits - withdrawals;
}

/**
 * Contest gain requires a MetaStats sync and deposit baseline — never infer from stale fields.
 * @param {object} account
 * @param {{ requireSyncedAt?: boolean }} [options]
 */
function canComputeContestGainFromAccount(account, options = {}) {
  const { requireSyncedAt = true } = options;
  if (requireSyncedAt && !account.metaapi_metrics_synced_at) {
    return false;
  }

  const netDeposits = resolveNetDeposits(account);
  if (netDeposits < MIN_CONTEST_BASELINE) {
    return false;
  }

  return true;
}

/** Realized gain — profit / netDeposits (matches admin account.gain). */
function deriveBalanceGainFromDeposits(account) {
  const profit = asFiniteNumber(account.profit, Number.NaN);
  const netDeposits = resolveNetDeposits(account);
  if (!Number.isFinite(profit) || netDeposits < MIN_CONTEST_BASELINE) return null;
  return sanitizeContestGainPercent((profit / netDeposits) * 100);
}

/** Live equity gain including open positions — (equity - netDeposits) / netDeposits. */
function deriveEquityGainFromDeposits(account) {
  const equity = asFiniteNumber(account.equity ?? account.balance, Number.NaN);
  const netDeposits = resolveNetDeposits(account);
  if (!Number.isFinite(equity) || netDeposits < MIN_CONTEST_BASELINE) return null;
  return sanitizeContestGainPercent(((equity - netDeposits) / netDeposits) * 100);
}

/**
 * @param {object} contest
 * @param {object} account MetaStats-synced trading account or live snapshot
 * @param {{ requireSyncedAt?: boolean }} [options]
 * @returns {number|null}
 */
function resolveContestGainFromAccount(contest, account, options = {}) {
  if (!canComputeContestGainFromAccount(account, options)) {
    return null;
  }

  const basis = resolveGainBasis(contest);
  if (basis === 'equity') {
    return deriveEquityGainFromDeposits(account);
  }
  return deriveBalanceGainFromDeposits(account);
}

/**
 * @param {object} contest
 * @param {object} account
 * @param {{ totalLot?: number, entry?: object, requireSyncedAt?: boolean }} [options]
 * @returns {{ ok: true, metrics: object } | { ok: false, reason: string }}
 */
function buildContestLeaderboardMetricsFromAccount(contest, account, options = {}) {
  const { totalLot = 0, entry = {}, requireSyncedAt = true } = options;
  const gain = resolveContestGainFromAccount(contest, account, { requireSyncedAt });
  if (gain == null) {
    return { ok: false, reason: 'metastats_gain_not_computable' };
  }

  const balance = asFiniteNumber(account.balance, 0);
  const equity = asFiniteNumber(account.equity ?? balance, balance);

  return {
    ok: true,
    metrics: {
      gain,
      dd: asFiniteNumber(account.dd, 0),
      profit: asFiniteNumber(account.profit, 0),
      balance,
      equity,
      peak_equity: asFiniteNumber(entry.peak_equity, equity),
      lowest_equity: asFiniteNumber(entry.lowest_equity, equity),
      total_lot: totalLot,
    },
  };
}

module.exports = {
  resolveNetDeposits,
  canComputeContestGainFromAccount,
  deriveBalanceGainFromDeposits,
  deriveEquityGainFromDeposits,
  resolveContestGainFromAccount,
  buildContestLeaderboardMetricsFromAccount,
};
