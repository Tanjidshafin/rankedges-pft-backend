import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  compareContestLeaderboardEntries,
  ranksByGain,
  resolveLeaderboardScore,
  sortContestLeaderboardEntries,
} from '../backend/contestRanking.js';
import { buildContestScopedMetrics } from '../backend/contestScopedMetrics.js';

const standardContest = { type: 'standard', scoring_mode: 'gain' };

describe('contestRanking', () => {
  it('ranksByGain is true for standard contests', () => {
    assert.equal(ranksByGain(standardContest), true);
  });

  it('resolveLeaderboardScore uses gain for standard contests', () => {
    assert.equal(
      resolveLeaderboardScore(standardContest, { gain: 12.5, dd: 3, profit: 100, balance: 1100 }, 4.2),
      12.5,
    );
  });

  it('sorts by gain when all scores are zero', () => {
    const entries = [
      { user_id: 'a', gain: 5.3, score: 0, dd: 10, total_lot: 2 },
      { user_id: 'b', gain: 162.73, score: 0, dd: 5, total_lot: 1 },
      { user_id: 'c', gain: 148.8, score: 0, dd: 8, total_lot: 3 },
    ];

    const sorted = [...entries].sort((left, right) =>
      compareContestLeaderboardEntries(standardContest, left, right),
    );

    assert.deepEqual(
      sorted.map((entry) => entry.user_id),
      ['b', 'c', 'a'],
    );
  });

  it('tie-breaks equal gain by lower total_lot', () => {
    const left = { user_id: 'a', gain: 10, score: 10, dd: 2, total_lot: 5 };
    const right = { user_id: 'b', gain: 10, score: 10, dd: 2, total_lot: 2 };

    assert.ok(compareContestLeaderboardEntries(standardContest, right, left) < 0);
  });

  it('sortContestLeaderboardEntries orders by gain when score is stale zero', () => {
    const entries = [
      { user_id: 'negative', gain: -10.5, score: 0, dd: 1, total_lot: 0, rank: 34 },
      { user_id: 'positive', gain: 2.37, score: 0, dd: 1, total_lot: 0, rank: 36 },
      { user_id: 'flat', gain: 0, score: 0, dd: 1, total_lot: 0, rank: 35 },
    ];

    const ranked = sortContestLeaderboardEntries(standardContest, entries);
    assert.deepEqual(
      ranked.map((entry) => entry.user_id),
      ['positive', 'flat', 'negative'],
    );
    assert.equal(ranked[0].score, 2.37);
    assert.equal(ranked[2].score, -10.5);
  });
});

describe('contestScopedMetrics', () => {
  it('sets score equal to gain for standard contests', () => {
    const contest = {
      type: 'standard',
      scoring_mode: 'gain',
      gain_basis: 'equity',
      start_at: '2026-06-15T00:00:00.000Z',
      end_at: '2026-07-10T23:59:00.000Z',
    };
    const account = { balance: 1200, equity: 1250, gain: 25, profit: 250, dd: 4 };
    const entry = { starting_balance: 1000, starting_equity: 1000, peak_equity: 1300, lowest_equity: 980 };

    const metrics = buildContestScopedMetrics(contest, account, entry, []);

    assert.equal(metrics.gain, 25);
    assert.equal(metrics.score, 25);
    assert.equal(metrics.total_lot, 0);
  });
});
