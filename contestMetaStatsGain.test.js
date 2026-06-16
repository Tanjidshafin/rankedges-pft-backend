const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  canComputeContestGainFromAccount,
  resolveContestGainFromAccount,
  deriveBalanceGainFromDeposits,
  deriveEquityGainFromDeposits,
} = require('./contestMetaStatsGain');

const balanceContest = { type: 'standard', gain_basis: 'balance' };
const equityContest = { type: 'standard', gain_basis: 'equity' };

const syncedAt = '2026-06-15T12:00:00.000Z';

describe('contestMetaStatsGain', () => {
  it('balance basis uses profit/netDeposits (login 517537 admin parity)', () => {
    const account = {
      metaapi_metrics_synced_at: syncedAt,
      gain: -85.64,
      profit: -1712.8,
      balance: 287.12,
      equity: 287.12,
      metaapi_deposits: 2000,
      metaapi_withdrawals: 0,
    };
    assert.equal(resolveContestGainFromAccount(balanceContest, account), -85.64);
    assert.equal(deriveBalanceGainFromDeposits(account), -85.64);
  });

  it('balance basis computes from profit when gain field missing', () => {
    const account = {
      metaapi_metrics_synced_at: syncedAt,
      profit: -500,
      metaapi_deposits: 10000,
      metaapi_withdrawals: 0,
    };
    assert.equal(deriveBalanceGainFromDeposits(account), -5);
  });

  it('equity basis uses equity vs netDeposits (includes open float)', () => {
    const account = {
      metaapi_metrics_synced_at: syncedAt,
      equity: 287.12,
      balance: 287.12,
      metaapi_deposits: 2000,
      metaapi_withdrawals: 0,
    };
    assert.equal(deriveEquityGainFromDeposits(account), -85.64);
    assert.equal(resolveContestGainFromAccount(equityContest, account), -85.64);
  });

  it('ignores corrupt account.gain when deposits allow recalculation', () => {
    const account = {
      metaapi_metrics_synced_at: syncedAt,
      gain: -121.85,
      profit: -1712.8,
      balance: 287.12,
      equity: 287.12,
      metaapi_deposits: 2000,
      metaapi_withdrawals: 0,
    };
    assert.equal(resolveContestGainFromAccount(balanceContest, account), -85.64);
  });

  it('returns null when account has not been MetaStats synced', () => {
    const account = {
      profit: -500,
      metaapi_deposits: 10000,
      metaapi_withdrawals: 0,
    };
    assert.equal(canComputeContestGainFromAccount(account), false);
    assert.equal(resolveContestGainFromAccount(balanceContest, account), null);
  });

  it('returns null when netDeposits below minimum', () => {
    const account = {
      metaapi_metrics_synced_at: syncedAt,
      equity: 100,
      metaapi_deposits: 5,
      metaapi_withdrawals: 0,
    };
    assert.equal(deriveEquityGainFromDeposits(account), null);
    assert.equal(resolveContestGainFromAccount(equityContest, account), null);
  });
});
