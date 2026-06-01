/**
 * PFT contest gain, field mapping, and ranking (equity_vs_starting_balance_v1).
 */

const PFT_GAIN_FORMULA_VERSION = 'equity_vs_starting_balance_v1';
const PFT_GAIN_BASELINE_TYPE = 'starting_balance';

function asFiniteNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function calculatePftGainPercent(equity, startingBalance) {
  const baseline = asFiniteNumber(startingBalance, 0);
  const eq = asFiniteNumber(equity, 0);
  if (baseline <= 0) return 0;
  return Number((((eq - baseline) / baseline) * 100).toFixed(4));
}

function calculatePftLiveDrawdown(peakEquity, lowestEquity) {
  const peak = asFiniteNumber(peakEquity, 0);
  const low = asFiniteNumber(lowestEquity, 0);
  if (peak <= 0) return 0;
  return Number((((peak - low) / peak) * 100).toFixed(4));
}

function mapPftParticipantStatusToContest(status) {
  const normalized = String(status || 'active');
  if (normalized === 'disqualified') return 'disqualified';
  if (normalized === 'completed') return 'completed';
  return 'active';
}

function parseIsoMs(value) {
  if (!value) return 0;
  const ms = new Date(value).getTime();
  return Number.isNaN(ms) ? 0 : ms;
}

/**
 * Compare two leaderboard rows for PFT ranking (higher rank = sort earlier).
 */
function comparePftLeaderboardEntries(left, right, options = {}) {
  const leftScore = asFiniteNumber(left.score ?? left.gain, 0);
  const rightScore = asFiniteNumber(right.score ?? right.gain, 0);
  if (rightScore !== leftScore) {
    return rightScore - leftScore;
  }

  if (options.rankingsLocked && options.captureTimestamp) {
    const captureDiff = parseIsoMs(left.pft_captured_at) - parseIsoMs(right.pft_captured_at);
    if (captureDiff !== 0) return captureDiff;
  }

  const leftDd = asFiniteNumber(left.dd, 0);
  const rightDd = asFiniteNumber(right.dd, 0);
  if (leftDd !== rightDd) {
    return leftDd - rightDd;
  }

  const joinDiff = parseIsoMs(left.pft_joined_at) - parseIsoMs(right.pft_joined_at);
  if (joinDiff !== 0) return joinDiff;

  return String(left.account_id || '').localeCompare(String(right.account_id || ''));
}

/**
 * Assign ranks to deduped entries; disqualified rows rank after all active.
 */
function rankPftLeaderboardEntries(entries, options = {}) {
  const active = entries.filter((entry) => entry.participant_status !== 'disqualified');
  const disqualified = entries.filter((entry) => entry.participant_status === 'disqualified');

  const sortedActive = [...active].sort((left, right) => comparePftLeaderboardEntries(left, right, options));
  const allRanked = [...sortedActive, ...disqualified];

  return allRanked.map((entry, index) => ({
    ...entry,
    rank: index + 1,
  }));
}

/**
 * Build leaderboard document fields from PFT participant + account (+ optional snapshot).
 */
function buildPftLeaderboardFields({
  participant,
  account,
  snapshot,
  batch,
  existingEntry,
  rankingsLocked,
  maskAccountRef,
  resolvePlatform,
}) {
  const accountId = String(participant?.accountId || account?.id || '');
  const startingBalance = asFiniteNumber(
    participant?.startingBalance ?? existingEntry?.starting_balance ?? account?.balance,
    0,
  );
  const startingEquity = asFiniteNumber(
    participant?.startingEquity ?? existingEntry?.pft_starting_equity ?? account?.equity ?? startingBalance,
    startingBalance,
  );
  const joinedAt = participant?.joinedAt || participant?.startTimestamp || existingEntry?.pft_joined_at || new Date().toISOString();
  const participantStatus = mapPftParticipantStatusToContest(participant?.status);
  const platform = typeof resolvePlatform === 'function'
    ? resolvePlatform(account, participant, snapshot)
    : (participant?.platform || account?.platform || 'unknown');

  const batchId = String(batch?.id || participant?.batchId || '');
  const batchNumber = Number(batch?.batchNumber ?? existingEntry?.pft_batch_number ?? 0) || undefined;

  const basePft = {
    pft_participant_id: participant?.id ? String(participant.id) : existingEntry?.pft_participant_id,
    pft_batch_id: batchId || existingEntry?.pft_batch_id,
    pft_batch_number: batchNumber,
    pft_starting_equity: startingEquity,
    pft_baseline_value: startingBalance,
    pft_gain_baseline_type: PFT_GAIN_BASELINE_TYPE,
    pft_gain_formula_version: PFT_GAIN_FORMULA_VERSION,
    platform,
    masked_account_ref: maskAccountRef ? maskAccountRef(accountId) : existingEntry?.masked_account_ref,
    pft_joined_at: joinedAt,
    starting_balance: startingBalance,
    participant_status: participantStatus,
  };

  if (participantStatus === 'disqualified') {
    return {
      ...basePft,
      gain: asFiniteNumber(existingEntry?.gain, 0),
      score: asFiniteNumber(existingEntry?.score, 0),
      dd: asFiniteNumber(existingEntry?.dd, 0),
      profit: asFiniteNumber(existingEntry?.profit, 0),
      balance: asFiniteNumber(existingEntry?.balance, startingBalance),
      peak_equity: asFiniteNumber(existingEntry?.peak_equity, startingEquity),
      lowest_equity: asFiniteNumber(existingEntry?.lowest_equity, startingEquity),
      pft_final_equity: existingEntry?.pft_final_equity,
      pft_final_balance: existingEntry?.pft_final_balance,
      pft_disqualified_at: participant?.disqualifiedAt || existingEntry?.pft_disqualified_at || new Date().toISOString(),
      pft_disqualified_reason: participant?.disqualifiedReason || existingEntry?.pft_disqualified_reason || 'Disqualified',
    };
  }

  const useCompletedSnapshot = rankingsLocked && snapshot?.status === 'completed';
  if (useCompletedSnapshot) {
    const finalEquity = asFiniteNumber(snapshot.finalEquity ?? snapshot.finalBalance, startingEquity);
    const finalBalance = asFiniteNumber(snapshot.finalBalance, finalEquity);
    const gainPercent = asFiniteNumber(snapshot.gainPercent, calculatePftGainPercent(finalEquity, startingBalance));
    const profit = Number((finalEquity - startingBalance).toFixed(2));

    return {
      ...basePft,
      gain: gainPercent,
      score: gainPercent,
      dd: asFiniteNumber(snapshot.drawdownAtCapture, 0),
      profit,
      balance: finalEquity,
      peak_equity: Math.max(finalEquity, startingEquity),
      lowest_equity: Math.min(finalEquity, startingEquity),
      pft_final_equity: finalEquity,
      pft_final_balance: finalBalance,
      pft_captured_at: snapshot.captureTimestamp || existingEntry?.pft_captured_at,
      participant_status: 'completed',
    };
  }

  const currentEquity = asFiniteNumber(account?.equity ?? account?.balance, startingEquity);
  const prevPeak = asFiniteNumber(existingEntry?.peak_equity, startingEquity);
  const prevLow = asFiniteNumber(existingEntry?.lowest_equity, startingEquity);
  const peakEquity = Math.max(prevPeak, currentEquity, startingEquity);
  const lowestEquity = Math.min(prevLow, currentEquity, startingEquity);
  const gain = calculatePftGainPercent(currentEquity, startingBalance);
  const dd = calculatePftLiveDrawdown(peakEquity, lowestEquity);
  const profit = Number((currentEquity - startingBalance).toFixed(2));

  return {
    ...basePft,
    gain,
    score: gain,
    dd,
    profit,
    balance: currentEquity,
    peak_equity: peakEquity,
    lowest_equity: lowestEquity,
    pft_final_equity: currentEquity,
    pft_final_balance: asFiniteNumber(account?.balance, currentEquity),
    participant_status: participantStatus === 'completed' ? 'completed' : 'active',
  };
}

module.exports = {
  PFT_GAIN_FORMULA_VERSION,
  PFT_GAIN_BASELINE_TYPE,
  calculatePftGainPercent,
  calculatePftLiveDrawdown,
  mapPftParticipantStatusToContest,
  comparePftLeaderboardEntries,
  rankPftLeaderboardEntries,
  buildPftLeaderboardFields,
};
