const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { buildContestScopedMetrics, buildContestScopedMetricsFromMetaApi } = require('./contestScopedMetrics');

const contest = {
  id: 'c1',
  type: 'standard',
  gain_basis: 'balance',
  start_at: '2026-01-01T00:00:00.000Z',
  end_at: '2026-12-31T23:59:59.000Z',
};

describe('buildContestScopedMetrics', () => {
  it('uses reconstructed contest-start balance when starting_balance is missing', () => {
    const account = { id: 'a1', user_id: 'u1', balance: 9500, equity: 9500, gain: -1e20, profit: -500, dd: 0 };
    const entry = { starting_balance: 0, starting_equity: 0, peak_equity: 0, lowest_equity: 0 };
    const trades = [
      {
        type: 'DEAL_TYPE_BUY',
        volume: 0.1,
        profit: -500,
        swap: 0,
        commission: 0,
        closeTime: '2026-06-01T12:00:00.000Z',
      },
    ];

    const metrics = buildContestScopedMetrics(contest, account, entry, trades);
    assert.equal(metrics.gain, -5);
    assert.ok(Math.abs(metrics.score) < 1_000);
  });

  it('ignores corrupt tiny starting_balance when trade replay reconstructs contest start', () => {
    const account = { id: 'a3', user_id: 'u3', balance: 9500, equity: 9500, gain: 0, profit: -500, dd: 0 };
    const entry = { starting_balance: 5, starting_equity: 5, peak_equity: 10000, lowest_equity: 10000 };
    const trades = [
      {
        type: 'DEAL_TYPE_SELL',
        volume: 0.2,
        profit: -500,
        swap: 0,
        commission: 0,
        closeTime: '2026-06-02T12:00:00.000Z',
      },
    ];

    const metrics = buildContestScopedMetrics(contest, account, entry, trades);
    assert.equal(metrics.gain, -5);
    assert.equal(metrics.resolved_baseline, 10000);
  });

  it('computes contest gain from profit over starting_balance', () => {
    const account = { id: 'a2', user_id: 'u2', balance: 9500, equity: 9500, gain: 0, profit: -500, dd: 0 };
    const entry = { starting_balance: 10000, starting_equity: 10000, peak_equity: 10000, lowest_equity: 10000 };
    const trades = [
      {
        type: 'DEAL_TYPE_SELL',
        volume: 0.2,
        profit: -500,
        swap: 0,
        commission: 0,
        closeTime: '2026-06-02T12:00:00.000Z',
      },
    ];

    const metrics = buildContestScopedMetrics(contest, account, entry, trades);
    assert.equal(metrics.gain, -5);
    assert.equal(metrics.score, -5);
  });
});

describe('buildContestScopedMetricsFromMetaApi', () => {
  it('reconstructs gain when starting_balance is missing', () => {
    const liveAccount = { balance: 9500, equity: 9500, gain: 99, profit: -500, dd: 0 };
    const entry = { starting_balance: 0, starting_equity: 0, peak_equity: 0, lowest_equity: 0 };
    const deals = [{ type: 'DEAL_TYPE_BUY', volume: 0.1, profit: -500, swap: 0, commission: 0, time: '2026-06-01T12:00:00.000Z' }];

    const metrics = buildContestScopedMetricsFromMetaApi(contest, liveAccount, entry, deals, 'mt5');
    assert.equal(metrics.gain, -5);
    assert.equal(metrics.resolved_baseline, 10000);
  });

  it('ignores corrupt tiny starting_balance for MetaApi sync', () => {
    const liveAccount = { balance: 9500, equity: 9500, gain: -197835, profit: -9891, dd: 0 };
    const entry = { starting_balance: 5, starting_equity: 5, peak_equity: 10000, lowest_equity: 10000 };
    const deals = [{ type: 'DEAL_TYPE_BUY', volume: 0.1, profit: -500, swap: 0, commission: 0, time: '2026-06-01T12:00:00.000Z' }];

    const metrics = buildContestScopedMetricsFromMetaApi(contest, liveAccount, entry, deals, 'mt5');
    assert.equal(metrics.gain, -5);
    assert.ok(Math.abs(metrics.gain) < 1000);
  });

  it('uses live account metrics for equity-basis contests', () => {
    const equityContest = { ...contest, gain_basis: 'equity' };
    const liveAccount = { balance: 11000, equity: 12000, gain: 20, profit: 2000, dd: 5 };
    const entry = { starting_balance: 10000, starting_equity: 10000, peak_equity: 12000, lowest_equity: 10000 };

    const metrics = buildContestScopedMetricsFromMetaApi(equityContest, liveAccount, entry, [], 'mt5');
    assert.equal(metrics.gain, 20);
    assert.equal(metrics.equity, 12000);
  });
});
