/**
 * 3v3 team ranking — mirror of client updateContestRankings 3v3 branch.
 */

const { compareContestLeaderboardEntries } = require('./contestRanking');

/**
 * @param {object} contest
 * @param {object[]} dedupedEntries leaderboard rows (one per user)
 * @param {object[]} roomMembers contestRoomMembers rows
 * @returns {Array<object & { rank: number }>}
 */
function rank3v3LeaderboardEntries(contest, dedupedEntries, roomMembers) {
  const memberByUser = new Map();
  for (const member of roomMembers) {
    memberByUser.set(String(member.user_id), member);
  }

  const byRoomAndTeam = new Map();
  const fallbackEntries = [];

  for (const entry of dedupedEntries) {
    const membership = memberByUser.get(String(entry.user_id));
    if (!membership?.room_id || !membership.team) {
      fallbackEntries.push(entry);
      continue;
    }

    const key = `${membership.room_id}:${membership.team}`;
    const teamEntries = byRoomAndTeam.get(key) || [];
    teamEntries.push(entry);
    byRoomAndTeam.set(key, teamEntries);
  }

  const roomScores = new Map();
  for (const [key, entries] of byRoomAndTeam.entries()) {
    const [roomId, team] = key.split(':');
    const totalGain = entries.reduce((sum, row) => sum + (Number(row.gain) || 0), 0);
    const teamScore =
      contest.team_scoring_mode === 'average' ? totalGain / entries.length : totalGain;

    const scores = roomScores.get(roomId) || [];
    scores.push({ roomId, team, score: teamScore, entries });
    roomScores.set(roomId, scores);
  }

  const ranked = [];

  for (const teams of roomScores.values()) {
    teams.sort((left, right) => {
      if (right.score !== left.score) return right.score - left.score;
      const leftAvgDd =
        left.entries.reduce((sum, row) => sum + (Number(row.dd) || 0), 0) / left.entries.length;
      const rightAvgDd =
        right.entries.reduce((sum, row) => sum + (Number(row.dd) || 0), 0) / right.entries.length;
      return leftAvgDd - rightAvgDd;
    });

    if (teams.length === 1) {
      for (const entry of teams[0].entries) {
        ranked.push({ ...entry, rank: 1 });
      }
      continue;
    }

    const [first, second] = teams;
    const tie = first.score === second.score;
    for (const entry of first.entries) {
      ranked.push({ ...entry, rank: 1 });
    }
    for (const entry of second.entries) {
      ranked.push({ ...entry, rank: tie ? 1 : 2 });
    }
  }

  const fallbackSorted = [...fallbackEntries].sort((left, right) =>
    compareContestLeaderboardEntries(contest, left, right),
  );
  fallbackSorted.forEach((entry, index) => {
    ranked.push({ ...entry, rank: 3 + index });
  });

  return ranked;
}

module.exports = {
  rank3v3LeaderboardEntries,
};
