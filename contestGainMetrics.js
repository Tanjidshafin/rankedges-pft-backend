/**
 * Contest gain metrics — mirror of src/lib/contestGainMetrics.ts for backend sync.
 */

const DEFAULT_GAIN_BASIS = 'equity';
const LEGACY_GAIN_BASIS = 'balance';
const MIN_CONTEST_BASELINE = 10;
const BASELINE_MISMATCH_RATIO = 4;

function asFiniteNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

/** Reject corrupt or astronomical gain values before Firestore persist. */
function sanitizeContestGainPercent(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  if (Math.abs(n) > 10_000) return 0;
  return Number(n.toFixed(2));
}

/**
 * Pick a contest gain denominator when stored baseline may be missing or corrupt.
 * Prefers reconstructed contest-start balance from trade replay when stored is tiny or mismatched.
 */
function resolveContestGainBaseline(storedBaseline, syntheticBaseline, terminalFallback = 0) {
  const stored = asFiniteNumber(storedBaseline, 0);
  const synthetic = asFiniteNumber(syntheticBaseline, 0);
  const terminal = asFiniteNumber(terminalFallback, 0);

  if (stored >= MIN_CONTEST_BASELINE) {
    if (synthetic >= MIN_CONTEST_BASELINE) {
      const ratio = stored / synthetic;
      if (ratio < 1 / BASELINE_MISMATCH_RATIO || ratio > BASELINE_MISMATCH_RATIO) {
        return synthetic;
      }
    }
    return stored;
  }

  if (synthetic >= MIN_CONTEST_BASELINE) return synthetic;
  if (terminal >= MIN_CONTEST_BASELINE) return terminal;
  return 0;
}

function contestGainPercentFromTradeMetrics(metrics, resolvedBaseline) {
  const baseline = asFiniteNumber(resolvedBaseline, 0);
  if (baseline < MIN_CONTEST_BASELINE) return 0;
  return sanitizeContestGainPercent((asFiniteNumber(metrics.profit, 0) / baseline) * 100);
}

function resolveGainBasis(contest) {
  if (!contest || contest.type === 'pft') {
    return LEGACY_GAIN_BASIS;
  }
  return contest.gain_basis === 'equity' ? 'equity' : LEGACY_GAIN_BASIS;
}

function resolveCurrentEquity(account) {
  if (!account) return 0;
  const equity = asFiniteNumber(account.equity, Number.NaN);
  if (Number.isFinite(equity)) return equity;
  return asFiniteNumber(account.balance, 0);
}

function resolveCurrentBalance(account) {
  return asFiniteNumber(account?.balance, 0);
}

function calculateContestGainPercent(input) {
  const { gainBasis, startingBalance, startingEquity, currentBalance, currentEquity } = input;

  if (gainBasis === 'equity') {
    const baseline = asFiniteNumber(startingEquity ?? startingBalance, 0);
    if (baseline <= 0) return 0;
    return sanitizeContestGainPercent(((currentEquity - baseline) / baseline) * 100);
  }

  const baseline = asFiniteNumber(startingBalance, 0);
  if (baseline <= 0) return 0;
  return sanitizeContestGainPercent(((currentBalance - baseline) / baseline) * 100);
}

function resolvePerformanceValue(gainBasis, currentBalance, currentEquity) {
  return gainBasis === 'equity' ? currentEquity : currentBalance;
}

function updatePerformanceWatermarks(input) {
  const current = resolvePerformanceValue(input.gainBasis, input.currentBalance, input.currentEquity);
  const seedPeak = input.peak > 0 ? input.peak : current;
  const seedLow = input.lowest > 0 ? input.lowest : current;

  return {
    peak: Math.max(seedPeak, current),
    lowest: Math.min(seedLow, current),
  };
}

function calculateContestDrawdownPercent(peak, lowest) {
  const peakValue = asFiniteNumber(peak, 0);
  const lowValue = asFiniteNumber(lowest, 0);
  if (peakValue <= 0) return 0;
  return Number((((peakValue - lowValue) / peakValue) * 100).toFixed(2));
}

function buildLeaderboardMetricUpdate(input) {
  const gainBasis = resolveGainBasis(input.contest);
  const currentBalance = resolveCurrentBalance(input.account);
  const currentEquity = resolveCurrentEquity(input.account);
  const startingBalance = asFiniteNumber(input.entry.starting_balance, 0);
  const startingEquity = asFiniteNumber(input.entry.starting_equity, startingBalance);

  const watermarks = updatePerformanceWatermarks({
    gainBasis,
    peak: asFiniteNumber(input.entry.peak_equity, 0),
    lowest: asFiniteNumber(input.entry.lowest_equity, 0),
    currentBalance,
    currentEquity,
  });

  let gain;
  if (gainBasis === 'equity') {
    gain = calculateContestGainPercent({
      gainBasis,
      startingBalance,
      startingEquity,
      currentBalance,
      currentEquity,
    });
  } else if (input.contestScopedGain !== undefined) {
    gain = sanitizeContestGainPercent(asFiniteNumber(input.contestScopedGain, 0));
  } else {
    gain = calculateContestGainPercent({
      gainBasis,
      startingBalance,
      startingEquity,
      currentBalance,
      currentEquity,
    });
  }

  const dd =
    input.contestScopedDd !== undefined && gainBasis === 'balance'
      ? asFiniteNumber(input.contestScopedDd, 0)
      : calculateContestDrawdownPercent(watermarks.peak, watermarks.lowest);

  const profit =
    input.contestScopedProfit !== undefined && gainBasis === 'balance'
      ? asFiniteNumber(input.contestScopedProfit, 0)
      : asFiniteNumber(input.account.profit, 0);

  return {
    gain: sanitizeContestGainPercent(gain),
    dd,
    profit,
    balance: currentBalance,
    equity: currentEquity,
    peak_equity: watermarks.peak,
    lowest_equity: watermarks.lowest,
  };
}

module.exports = {
  DEFAULT_GAIN_BASIS,
  LEGACY_GAIN_BASIS,
  MIN_CONTEST_BASELINE,
  sanitizeContestGainPercent,
  resolveContestGainBaseline,
  contestGainPercentFromTradeMetrics,
  resolveGainBasis,
  resolveCurrentEquity,
  resolveCurrentBalance,
  calculateContestGainPercent,
  updatePerformanceWatermarks,
  calculateContestDrawdownPercent,
  buildLeaderboardMetricUpdate,
};
