import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { rank1v1LeaderboardEntries } from './contestRanking1v1.js';

describe('rank1v1LeaderboardEntries', () => {
  it('assigns rank 1 to higher-gain player per room', () => {
    const contest = { type: '1v1', scoring_mode: 'gain' };
    const entries = [
      { id: 'a', user_id: 'u1', gain: 12, score: 12, dd: 1 },
      { id: 'b', user_id: 'u2', gain: 5, score: 5, dd: 1 },
    ];
    const members = [
      { user_id: 'u1', room_id: 'room1' },
      { user_id: 'u2', room_id: 'room1' },
    ];

    const ranked = rank1v1LeaderboardEntries(contest, entries, members);
    const rankByUser = Object.fromEntries(ranked.map((row) => [row.user_id, row.rank]));

    assert.equal(rankByUser.u1, 1);
    assert.equal(rankByUser.u2, 2);
  });
});
