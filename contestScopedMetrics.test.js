const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { buildContestScopedMetrics, buildContestScopedMetricsFromMetaApi } = require('./contestScopedMetrics');

const syncedAt = '2026-06-15T12:00:00.000Z';

const contest = {
  id: 'c1',
  type: 'standard',
  gain_basis: 'balance',
  start_at: '2026-01-01T00:00:00.000Z',
  end_at: '2026-12-31T23:59:59.000Z',
};

const metaStatsAccount = {
  metaapi_metrics_synced_at: syncedAt,
  gain: -85.64,
  profit: -1712.8,
  balance: 287.12,
  equity: 287.12,
  dd: 90,
  metaapi_deposits: 2000,
  metaapi_withdrawals: 0,
};

describe('buildContestScopedMetrics', () => {
  it('uses MetaStats profit/netDeposits, not trade replay', () => {
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

    const result = buildContestScopedMetrics(contest, metaStatsAccount, entry, trades);
    assert.equal(result.ok, true);
    assert.equal(result.metrics.gain, -85.64);
    assert.equal(result.metrics.balance, 287.12);
    assert.equal(result.metrics.total_lot, 0.2);
  });

  it('skips metrics when account is not MetaStats synced', () => {
    const entry = { starting_balance: 5, peak_equity: 10000, lowest_equity: 10000 };
    const unsynced = { ...metaStatsAccount, metaapi_metrics_synced_at: null };
    const result = buildContestScopedMetrics(contest, unsynced, entry, []);
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'metastats_gain_not_computable');
  });
});

describe('buildContestScopedMetricsFromMetaApi', () => {
  it('uses live MetaStats gain with contest-window lots', () => {
    const entry = { starting_balance: 5, peak_equity: 10000, lowest_equity: 10000 };
    const deals = [{ type: 'DEAL_TYPE_BUY', volume: 0.1, profit: -500, swap: 0, commission: 0, time: '2026-06-01T12:00:00.000Z' }];
    const liveAccount = { ...metaStatsAccount, metaapi_metrics_synced_at: syncedAt };

    const result = buildContestScopedMetricsFromMetaApi(contest, liveAccount, entry, deals, 'mt5');
    assert.equal(result.ok, true);
    assert.equal(result.metrics.gain, -85.64);
    assert.equal(result.metrics.total_lot, 0.1);
  });

  it('equity contest uses equity vs netDeposits', () => {
    const equityContest = { ...contest, gain_basis: 'equity' };
    const entry = { starting_equity: 10000, peak_equity: 12000, lowest_equity: 10000 };
    const liveAccount = {
      ...metaStatsAccount,
      metaapi_metrics_synced_at: syncedAt,
      equity: 12000,
      gain: 20,
    };

    const result = buildContestScopedMetricsFromMetaApi(equityContest, liveAccount, entry, [], 'mt5');
    assert.equal(result.ok, true);
    assert.equal(result.metrics.gain, 500);
  });
});
