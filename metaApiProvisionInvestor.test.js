const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const {
  formatErrorDetails,
  extractRecommendedResourceSlots,
  isResourceSlotsProvisioningError,
  formatMetaApiHttpErrorFromBody,
} = require('./metaApiHttpErrors');
const {
  resolveDefaultResourceSlots,
  buildProvisioningCreateBody,
  MAX_RESOURCE_SLOTS,
} = require('./metaApiProvisionInvestor');

describe('formatErrorDetails', () => {
  it('formats E_RESOURCE_SLOTS object without [object Object]', () => {
    const text = formatErrorDetails({ code: 'E_RESOURCE_SLOTS', recommendedResourceSlots: 2 });
    assert.equal(text, 'E_RESOURCE_SLOTS, recommendedResourceSlots=2');
  });
});

describe('extractRecommendedResourceSlots', () => {
  it('reads recommendedResourceSlots from MetaApi error body', () => {
    assert.equal(
      extractRecommendedResourceSlots({
        id: 4580,
        error: 'ValidationError',
        details: { code: 'E_RESOURCE_SLOTS', recommendedResourceSlots: 2 },
      }),
      2,
    );
  });
});

describe('isResourceSlotsProvisioningError', () => {
  it('detects E_RESOURCE_SLOTS on HTTP 400', () => {
    assert.equal(
      isResourceSlotsProvisioningError(400, {
        details: { code: 'E_RESOURCE_SLOTS' },
      }),
      true,
    );
  });

  it('ignores other HTTP 400 errors', () => {
    assert.equal(isResourceSlotsProvisioningError(400, { message: 'invalid login' }), false);
  });
});

describe('formatMetaApiHttpErrorFromBody', () => {
  it('includes recommendedResourceSlots in provision error text', () => {
    const msg = formatMetaApiHttpErrorFromBody(
      'provision-investor-account',
      400,
      'Bad Request',
      {
        id: 4580,
        error: 'ValidationError',
        message: 'Account resource slots should be equal or above estimated.',
        details: { code: 'E_RESOURCE_SLOTS', recommendedResourceSlots: 2 },
      },
      '',
    );
    assert.match(msg, /recommendedResourceSlots=2/);
    assert.doesNotMatch(msg, /\[object Object\]/);
  });
});

describe('resolveDefaultResourceSlots', () => {
  const original = process.env.METAAPI_PROVISIONING_RESOURCE_SLOTS;

  afterEach(() => {
    if (original === undefined) delete process.env.METAAPI_PROVISIONING_RESOURCE_SLOTS;
    else process.env.METAAPI_PROVISIONING_RESOURCE_SLOTS = original;
  });

  it('defaults to 1 slot', () => {
    delete process.env.METAAPI_PROVISIONING_RESOURCE_SLOTS;
    assert.equal(resolveDefaultResourceSlots({}), 1);
  });

  it('reads site settings override', () => {
    assert.equal(resolveDefaultResourceSlots({ metaapi_provisioning_resource_slots: 2 }), 2);
  });

  it('caps at MAX_RESOURCE_SLOTS', () => {
    assert.equal(resolveDefaultResourceSlots({ metaapi_provisioning_resource_slots: 99 }), MAX_RESOURCE_SLOTS);
  });
});

describe('buildProvisioningCreateBody', () => {
  it('includes resourceSlots in provisioning payload', () => {
    const body = buildProvisioningCreateBody({
      login: '126051',
      password: 'secret',
      server: 'AuricInternationalMarkets-Live',
      platform: 'mt5',
      reliability: 'regular',
      cloudType: 'cloud-g2',
      provisioningRegion: 'london',
      resourceSlots: 2,
    });
    assert.equal(body.resourceSlots, 2);
    assert.equal(body.metastatsApiEnabled, true);
  });
});
