const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  compoundRateToPercent,
  gainMultiplierToPercent,
  mapMetaStatsToAccountMetrics,
  normalizeDailyGrowthSeries,
} = require('./metaApiMetaStats');

describe('compoundRateToPercent', () => {
  it('converts MetaStats doc dailyGain decimal rate', () => {
    assert.equal(compoundRateToPercent(0.02299061669379654), 2.3);
  });

  it('converts MetaStats doc monthlyGain decimal rate', () => {
    assert.equal(compoundRateToPercent(0.7012819632221667), 70.13);
  });

  it('passes through live API percent values (>= 2)', () => {
    assert.equal(compoundRateToPercent(12.12), 12.12);
    assert.equal(compoundRateToPercent(-76.99), -76.99);
  });

  it('converts docs-format 12% rate', () => {
    assert.equal(compoundRateToPercent(0.1212), 12.12);
  });

  it('handles multiplier misplaced in compound-rate field (1.1212 → 12.12%)', () => {
    assert.equal(compoundRateToPercent(1.1212), 12.12);
  });

  it('fixes inflated dailyGain from old ratioToPercentDisplay (1.0169 → 1.69%, not 101.69%)', () => {
    assert.equal(compoundRateToPercent(1.0169), 1.69);
  });

  it('handles negative decimal rates', () => {
    assert.equal(compoundRateToPercent(-0.0803), -8.03);
  });

  it('handles negative multiplier-offset range', () => {
    assert.equal(compoundRateToPercent(-1.0803), -8.03);
  });

  it('returns null for invalid input and zero for zero', () => {
    assert.equal(compoundRateToPercent(null), null);
    assert.equal(compoundRateToPercent(undefined), null);
    assert.equal(compoundRateToPercent('nope'), null);
    assert.equal(compoundRateToPercent(0), 0);
  });
});

describe('gainMultiplierToPercent', () => {
  it('converts MetaStats absoluteGain multiplier', () => {
    assert.equal(gainMultiplierToPercent(1.1206999999999985), 112.07);
  });

  it('passes through large percent values already in display units', () => {
    assert.equal(gainMultiplierToPercent(-76.99), -76.99);
  });
});

describe('mapMetaStatsToAccountMetrics — login 169955 scenario', () => {
  it('reconciles daily gain with monthly for short-history account (verified Firestore raw)', () => {
    const mapped = mapMetaStatsToAccountMetrics({
      metrics: {
        dailyGain: 1.0169258524334923,
        monthlyGain: 12.116999999999978,
        gain: 12.117000000000022,
        absoluteGain: 12.116999999999999,
        profit: 121.17,
        deposits: 1000,
        withdrawals: 0,
        highestBalance: 1121.17,
        balance: 1121.17,
        equity: 1121.17,
        daysSinceTradingStarted: 0.12083172453703704,
        trades: 17,
        wonTradesPercent: 76.47,
      },
    });

    assert.equal(mapped.metaapi_daily_gain, 12.12);
    assert.equal(mapped.metaapi_monthly_gain, 12.12);
    assert.equal(mapped.profit, 121.17);
    assert.equal(mapped.metaapi_deposits, 1000);
    assert.equal(mapped.metaapi_highest_balance, 1121.17);
  });

  it('maps daily/monthly gain without 101.69% inflation when API sends mixed formats (no reconciliation)', () => {
    const mapped = mapMetaStatsToAccountMetrics({
      metrics: {
        dailyGain: 1.0169,
        monthlyGain: 12.12,
        gain: 1.1212,
        absoluteGain: 1.1212,
        profit: 121,
        deposits: 1000,
        withdrawals: 0,
        highestBalance: 1121,
        balance: 1121,
        equity: 1121,
        daysSinceTradingStarted: 30,
        trades: 1,
        wonTradesPercent: 100,
      },
    });

    assert.equal(mapped.metaapi_daily_gain, 1.69);
    assert.equal(mapped.metaapi_monthly_gain, 12.12);
    assert.equal(mapped.profit, 121);
    assert.equal(mapped.metaapi_deposits, 1000);
    assert.equal(mapped.metaapi_withdrawals, 0);
    assert.equal(mapped.metaapi_highest_balance, 1121);
  });

  it('maps daily gain equal to monthly when API sends docs-format rates', () => {
    const mapped = mapMetaStatsToAccountMetrics({
      metrics: {
        dailyGain: 0.1212,
        monthlyGain: 12.12,
        profit: 121,
        deposits: 1000,
        trades: 1,
        wonTradesPercent: 100,
      },
    });

    assert.equal(mapped.metaapi_daily_gain, 12.12);
    assert.equal(mapped.metaapi_monthly_gain, 12.12);
  });

  it('maps daily gain equal to monthly when API sends multiplier-style dailyGain', () => {
    const mapped = mapMetaStatsToAccountMetrics({
      metrics: {
        dailyGain: 1.1212,
        monthlyGain: 12.12,
        profit: 121,
        deposits: 1000,
        trades: 1,
        wonTradesPercent: 100,
      },
    });

    assert.equal(mapped.metaapi_daily_gain, 12.12);
    assert.equal(mapped.metaapi_monthly_gain, 12.12);
  });
});

describe('normalizeDailyGrowthSeries', () => {
  it('normalizes dailyGrowth gains using compound rate rules', () => {
    const series = normalizeDailyGrowthSeries([
      { date: '2026-05-25', balance: 1000, totalProfit: 0, totalGains: 0 },
      { date: '2026-06-05', balance: 1121, totalProfit: 121, totalGains: 0.1223, gains: 0.1223 },
    ]);

    assert.equal(series.length, 2);
    assert.equal(series[1].totalGains, 12.23);
    assert.equal(series[1].gains, 12.23);
  });

  it('passes through dailyGrowth totalGains already in percent', () => {
    const series = normalizeDailyGrowthSeries([
      { date: '2026-06-05', balance: 1121, totalProfit: 121, totalGains: 12.23, gains: 12.23 },
    ]);

    assert.equal(series[0].totalGains, 12.23);
    assert.equal(series[0].gains, 12.23);
  });
});
