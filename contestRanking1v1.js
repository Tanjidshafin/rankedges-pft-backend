/**
 * 1v1 room ranking — winner rank 1, loser rank 2 per room.
 */

const { compareContestLeaderboardEntries } = require('./contestRanking');

/**
 * @param {object} contest
 * @param {object[]} dedupedEntries
 * @param {object[]} roomMembers contestRoomMembers rows
 * @returns {Array<object & { rank: number }>}
 */
function rank1v1LeaderboardEntries(contest, dedupedEntries, roomMembers) {
  const memberByUser = new Map();
  for (const member of roomMembers) {
    memberByUser.set(String(member.user_id), member);
  }

  const byRoom = new Map();
  const fallbackEntries = [];

  for (const entry of dedupedEntries) {
    const membership = memberByUser.get(String(entry.user_id));
    if (!membership?.room_id) {
      fallbackEntries.push(entry);
      continue;
    }

    const roomEntries = byRoom.get(membership.room_id) || [];
    roomEntries.push(entry);
    byRoom.set(membership.room_id, roomEntries);
  }

  const ranked = [];

  for (const entries of byRoom.values()) {
    const sorted = [...entries].sort((left, right) =>
      compareContestLeaderboardEntries(contest, left, right),
    );
    sorted.forEach((entry, index) => {
      ranked.push({ ...entry, rank: index + 1 });
    });
  }

  const fallbackSorted = [...fallbackEntries].sort((left, right) =>
    compareContestLeaderboardEntries(contest, left, right),
  );
  const fallbackRankStart = byRoom.size + 1;
  fallbackSorted.forEach((entry, index) => {
    ranked.push({ ...entry, rank: fallbackRankStart + index });
  });

  return ranked;
}

module.exports = {
  rank1v1LeaderboardEntries,
};
