/**
 * Contest leaderboard ranking — compare entries and resolve scores.
 * Mirror of src/lib/contestRanking.ts
 */

function asFiniteNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function ranksByGain(contest) {
  if (!contest) return true;
  if (contest.type === 'standard') return true;
  return contest.scoring_mode === 'gain' || !contest.scoring_mode;
}

function calculateRiskAdjustedScore(gain, dd) {
  const ddPenalty = Math.max(0, 1 - asFiniteNumber(dd, 0) / 100);
  const gainValue = asFiniteNumber(gain, 0);
  return gainValue * ddPenalty * (1 + (gainValue > 0 ? 0.1 : 0));
}

function resolveLeaderboardScore(contest, metrics, totalLot = 0) {
  const gain = asFiniteNumber(metrics?.gain, 0);
  const dd = asFiniteNumber(metrics?.dd, 0);
  const profit = asFiniteNumber(metrics?.profit, 0);
  const balance = asFiniteNumber(metrics?.balance, 0);

  if (ranksByGain(contest)) {
    return gain;
  }

  switch (contest.scoring_mode) {
    case 'profit':
      return profit;
    case 'balance':
      return balance;
    case 'risk_adjusted':
      return calculateRiskAdjustedScore(gain, dd);
    case 'gain':
    default:
      return gain;
  }
}

function entryCreatedAtMs(entry) {
  const createdAt = entry?.createdAt;
  if (!createdAt) return 0;
  if (typeof createdAt.toMillis === 'function') return createdAt.toMillis();
  const ms = new Date(createdAt).getTime();
  return Number.isFinite(ms) ? ms : 0;
}

/**
 * Sort comparator for active leaderboard entries (higher rank = should appear first).
 * Returns negative when left should rank above right.
 */
function compareContestLeaderboardEntries(contest, left, right) {
  if (ranksByGain(contest)) {
    const gainDiff = asFiniteNumber(right.gain, 0) - asFiniteNumber(left.gain, 0);
    if (gainDiff !== 0) return gainDiff;

    const lotDiff = asFiniteNumber(left.total_lot, 0) - asFiniteNumber(right.total_lot, 0);
    if (lotDiff !== 0) return lotDiff;
  } else {
    const scoreDiff = asFiniteNumber(right.score, 0) - asFiniteNumber(left.score, 0);
    if (scoreDiff !== 0) return scoreDiff;

    const gainDiff = asFiniteNumber(right.gain, 0) - asFiniteNumber(left.gain, 0);
    if (gainDiff !== 0) return gainDiff;
  }

  const ddDiff = asFiniteNumber(left.dd, 0) - asFiniteNumber(right.dd, 0);
  if (ddDiff !== 0) return ddDiff;

  return entryCreatedAtMs(left) - entryCreatedAtMs(right);
}

function resolveLeaderboardEntryScore(contest, entry) {
  return resolveLeaderboardScore(
    contest,
    {
      gain: entry.gain,
      dd: entry.dd,
      profit: entry.profit,
      balance: entry.balance,
    },
    entry.total_lot ?? 0,
  );
}

function sortContestLeaderboardEntries(contest, entries) {
  const active = entries.filter(
    (entry) => entry.participant_status !== 'disqualified' && entry.participant_status !== 'withdrawn',
  );
  const inactive = entries.filter(
    (entry) => entry.participant_status === 'disqualified' || entry.participant_status === 'withdrawn',
  );
  const sorted = [...active].sort((left, right) => compareContestLeaderboardEntries(contest, left, right));

  return [...sorted, ...inactive].map((entry, index) => ({
    ...entry,
    rank: index + 1,
    score: resolveLeaderboardEntryScore(contest, entry),
  }));
}

module.exports = {
  ranksByGain,
  calculateRiskAdjustedScore,
  resolveLeaderboardScore,
  resolveLeaderboardEntryScore,
  sortContestLeaderboardEntries,
  entryCreatedAtMs,
  compareContestLeaderboardEntries,
};
