import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { rank3v3LeaderboardEntries } from './contestRanking3v3.js';

describe('rank3v3LeaderboardEntries', () => {
  it('assigns rank 1 to winning team and rank 2 to losing team per room', () => {
    const contest = { type: '3v3', team_scoring_mode: 'total', scoring_mode: 'gain' };
    const entries = [
      { id: 'a1', user_id: 'u1', gain: 10, dd: 2, score: 10 },
      { id: 'a2', user_id: 'u2', gain: 8, dd: 3, score: 8 },
      { id: 'b1', user_id: 'u3', gain: 5, dd: 1, score: 5 },
      { id: 'b2', user_id: 'u4', gain: 4, dd: 2, score: 4 },
    ];
    const members = [
      { user_id: 'u1', room_id: 'room1', team: 'A' },
      { user_id: 'u2', room_id: 'room1', team: 'A' },
      { user_id: 'u3', room_id: 'room1', team: 'B' },
      { user_id: 'u4', room_id: 'room1', team: 'B' },
    ];

    const ranked = rank3v3LeaderboardEntries(contest, entries, members);
    const rankByUser = Object.fromEntries(ranked.map((row) => [row.user_id, row.rank]));

    assert.equal(rankByUser.u1, 1);
    assert.equal(rankByUser.u2, 1);
    assert.equal(rankByUser.u3, 2);
    assert.equal(rankByUser.u4, 2);
  });

  it('ranks multiple rooms independently with duplicate rank 1 teams', () => {
    const contest = { type: '3v3', team_scoring_mode: 'total' };
    const entries = [
      { id: 'r1a', user_id: 'u1', gain: 20, dd: 1 },
      { id: 'r1b', user_id: 'u2', gain: 1, dd: 1 },
      { id: 'r2a', user_id: 'u3', gain: 15, dd: 1 },
      { id: 'r2b', user_id: 'u4', gain: 2, dd: 1 },
    ];
    const members = [
      { user_id: 'u1', room_id: 'room1', team: 'A' },
      { user_id: 'u2', room_id: 'room1', team: 'B' },
      { user_id: 'u3', room_id: 'room2', team: 'A' },
      { user_id: 'u4', room_id: 'room2', team: 'B' },
    ];

    const ranked = rank3v3LeaderboardEntries(contest, entries, members);
    const rankOnes = ranked.filter((row) => row.rank === 1).map((row) => row.user_id).sort();

    assert.deepEqual(rankOnes, ['u1', 'u3']);
  });
});
