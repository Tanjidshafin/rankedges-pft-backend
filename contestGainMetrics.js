/**
 * Contest gain metrics — mirror of src/lib/contestGainMetrics.ts for backend sync.
 */

const DEFAULT_GAIN_BASIS = 'equity';
const LEGACY_GAIN_BASIS = 'balance';

function asFiniteNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
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
  const {
    gainBasis,
    startingBalance,
    startingEquity,
    currentBalance,
    currentEquity,
    fallbackGain = 0,
  } = input;

  if (gainBasis === 'equity') {
    const baseline = asFiniteNumber(startingEquity ?? startingBalance, 0);
    if (baseline <= 0) return asFiniteNumber(fallbackGain, 0);
    return Number((((currentEquity - baseline) / baseline) * 100).toFixed(2));
  }

  const baseline = asFiniteNumber(startingBalance, 0);
  if (baseline <= 0) return asFiniteNumber(fallbackGain, 0);
  return Number((((currentBalance - baseline) / baseline) * 100).toFixed(2));
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

  const gain = calculateContestGainPercent({
    gainBasis,
    startingBalance,
    startingEquity,
    currentBalance,
    currentEquity,
    fallbackGain: asFiniteNumber(input.account.gain, 0),
  });

  const dd = calculateContestDrawdownPercent(watermarks.peak, watermarks.lowest);

  return {
    gain,
    dd,
    profit: asFiniteNumber(input.account.profit, 0),
    balance: currentBalance,
    equity: currentEquity,
    peak_equity: watermarks.peak,
    lowest_equity: watermarks.lowest,
  };
}

module.exports = {
  DEFAULT_GAIN_BASIS,
  LEGACY_GAIN_BASIS,
  resolveGainBasis,
  resolveCurrentEquity,
  resolveCurrentBalance,
  calculateContestGainPercent,
  updatePerformanceWatermarks,
  calculateContestDrawdownPercent,
  buildLeaderboardMetricUpdate,
};
