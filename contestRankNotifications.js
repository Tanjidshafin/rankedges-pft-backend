/**
 * Contest rank-change notifications (mirrors client notifyRankChange).
 */

function contestPublicPath(contest) {
  const segment = String(contest.slug || contest.id || '').trim();
  return segment ? `/contests/${segment}` : '/contests';
}

/**
 * @param {ReturnType<import('./notificationAdmin').createNotificationAdmin>} notificationAdmin
 * @param {{ id?: string, name?: string, slug?: string }} contest
 * @param {Map<string, number>} previousRanks user_id -> rank
 * @param {Array<{ user_id?: string, rank?: number, participant_status?: string }>} afterEntries
 */
async function notifyContestRankChanges(notificationAdmin, contest, previousRanks, afterEntries) {
  const contestName = contest.name || 'Contest';
  const link = contestPublicPath(contest);

  for (const entry of afterEntries) {
    if (!entry.user_id || entry.rank == null) continue;
    if (entry.participant_status === 'disqualified') continue;

    const newRank = Number(entry.rank);
    if (!Number.isFinite(newRank) || newRank > 3) continue;

    const previousRank = previousRanks.get(String(entry.user_id)) ?? null;
    if (previousRank !== null && previousRank <= newRank) continue;

    await notificationAdmin.createNotification({
      userId: String(entry.user_id),
      type: 'rank_change',
      title: `You moved up to Rank #${newRank}!`,
      message: `Congratulations! You're now ranked #${newRank} in "${contestName}". Keep up the great trading!`,
      link,
    });
  }
}

module.exports = {
  notifyContestRankChanges,
  contestPublicPath,
};
