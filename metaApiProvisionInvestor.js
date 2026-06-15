/**
 * Server-side MetaApi investor-password provisioning (uses site METAAPI token; never exposed to the browser).
 */
const crypto = require('crypto');
const {
  extractRecommendedResourceSlots,
  isResourceSlotsProvisioningError,
  formatMetaApiHttpErrorFromBody,
} = require('./metaApiHttpErrors');
const {
  normalizeMetaApiProvisioningAccountId,
  metaApiLoginVsUuidMessage,
} = require('./metaApiProvisioningId');

const PROVISIONING_API_BASE =
  process.env.META_API_PROVISIONING_BASE ||
  'https://mt-provisioning-api-v1.agiliumtrade.agiliumtrade.ai';

const MAX_RESOURCE_SLOTS = 10;
const MAX_RESOURCE_SLOT_RETRIES = 3;

function provisioningTransactionId() {
  return crypto.randomBytes(16).toString('hex');
}

function provisioningOptionsFromSiteSettings(settings) {
  const reliability = settings?.metaapi_provisioning_reliability === 'high' ? 'high' : 'regular';
  const cloudType = settings?.metaapi_provisioning_cloud_type === 'cloud-g1' ? 'cloud-g1' : 'cloud-g2';
  const raw = settings?.metaapi_provisioning_region;
  const region = typeof raw === 'string' && raw.trim() ? raw.trim() : 'new-york';
  return { reliability, cloudType, region };
}

function resolveDefaultResourceSlots(settings) {
  const fromSettings = Number(settings?.metaapi_provisioning_resource_slots);
  if (Number.isFinite(fromSettings) && fromSettings >= 1) {
    return Math.min(Math.trunc(fromSettings), MAX_RESOURCE_SLOTS);
  }
  const fromEnv = Number(process.env.METAAPI_PROVISIONING_RESOURCE_SLOTS);
  if (Number.isFinite(fromEnv) && fromEnv >= 1) {
    return Math.min(Math.trunc(fromEnv), MAX_RESOURCE_SLOTS);
  }
  return 1;
}

function buildProvisioningCreateBody(params) {
  const {
    login,
    password,
    server,
    platform,
    reliability,
    cloudType,
    provisioningRegion,
    resourceSlots,
  } = params;

  return {
    login,
    password,
    name: `${login}@${server}`,
    server,
    platform,
    magic: 0,
    quoteStreamingIntervalInSeconds: 2.5,
    application: 'MetaApi',
    type: cloudType,
    reliability,
    region: provisioningRegion,
    resourceSlots,
    metastatsApiEnabled: true,
  };
}

async function parseProvisioningFailure(response) {
  const status = response.status;
  let rawText = '';

  try {
    rawText = await response.text();
  } catch {
    rawText = '';
  }

  let parsed = null;
  if (rawText && rawText.trim()) {
    try {
      parsed = JSON.parse(rawText.trim());
    } catch {
      parsed = null;
    }
  }

  const message = formatMetaApiHttpErrorFromBody(
    'provision-investor-account',
    status,
    response.statusText || '',
    parsed,
    rawText,
  );

  return {
    message,
    isResourceSlotsError: isResourceSlotsProvisioningError(status, parsed),
    recommendedResourceSlots: extractRecommendedResourceSlots(parsed),
  };
}

async function listProvisioningAccounts(token) {
  const response = await fetch(`${PROVISIONING_API_BASE}/users/current/accounts`, {
    headers: {
      'auth-token': token,
      'Content-Type': 'application/json',
    },
  });
  if (!response.ok) return [];
  const data = await response.json();
  return Array.isArray(data) ? data : [];
}

async function resolveMetaApiCloudAccountId(token, createPayload, login) {
  const fromResponse = normalizeMetaApiProvisioningAccountId(createPayload.id);
  if (fromResponse) return fromResponse;

  const accounts = await listProvisioningAccounts(token);
  const loginStr = String(login).trim();
  const match = accounts.find((row) => String(row.login ?? '').trim() === loginStr);
  return match ? normalizeMetaApiProvisioningAccountId(match.id) : null;
}

async function postProvisioningAccount(apiToken, transactionId, createBody) {
  return fetch(`${PROVISIONING_API_BASE}/users/current/accounts`, {
    method: 'POST',
    headers: {
      'auth-token': apiToken,
      'Content-Type': 'application/json',
      'transaction-id': transactionId,
    },
    body: JSON.stringify(createBody),
  });
}

async function waitForProvisioningCreateResult(
  initialResponse,
  transactionId,
  apiToken,
  login,
  createBody,
) {
  let response = initialResponse;
  const deadline = Date.now() + 180_000;

  while (Date.now() < deadline) {
    if (response.status === 202) {
      const retryAfter = response.headers.get('Retry-After');
      let waitMs = 8000;
      if (retryAfter) {
        const asSec = Number(retryAfter);
        if (Number.isFinite(asSec) && asSec > 0) {
          waitMs = Math.min(45000, Math.max(2000, asSec * 1000));
        } else {
          const parsed = Date.parse(retryAfter);
          waitMs =
            Number.isFinite(parsed) ? Math.min(45000, Math.max(2000, parsed - Date.now())) : 8000;
        }
      }
      await new Promise((resolve) => setTimeout(resolve, waitMs));
      response = await postProvisioningAccount(apiToken, transactionId, createBody);
      continue;
    }

    if (!response.ok) {
      const failure = await parseProvisioningFailure(response);
      return {
        success: false,
        error: failure.message,
        isResourceSlotsError: failure.isResourceSlotsError,
        recommendedResourceSlots: failure.recommendedResourceSlots,
      };
    }

    const data = await response.json();
    const accountId = await resolveMetaApiCloudAccountId(apiToken, data, login);
    if (!accountId) {
      return {
        success: false,
        error: metaApiLoginVsUuidMessage(login),
      };
    }

    return {
      success: true,
      data: {
        accountId,
        token: apiToken,
        region:
          typeof data.region === 'string' && data.region.trim() ? data.region : createBody.region,
        resourceSlots: createBody.resourceSlots,
      },
    };
  }

  return {
    success: false,
    error: 'Broker setup is still in progress on MetaApi. Wait a minute and try connecting again.',
  };
}

/**
 * @param {string} apiToken
 * @param {Record<string, unknown>} settings
 * @param {{ login: string; password: string; server: string; platform: 'mt4' | 'mt5' }} params
 */
async function provisionInvestorMetaApiAccount(apiToken, settings, params) {
  const { login, password, server, platform } = params;
  const { reliability, cloudType, region: provisioningRegion } = provisioningOptionsFromSiteSettings(settings);
  let resourceSlots = resolveDefaultResourceSlots(settings);

  for (let slotAttempt = 0; slotAttempt < MAX_RESOURCE_SLOT_RETRIES; slotAttempt += 1) {
    const createBody = buildProvisioningCreateBody({
      login,
      password,
      server,
      platform,
      reliability,
      cloudType,
      provisioningRegion,
      resourceSlots,
    });
    const transactionId = provisioningTransactionId();

    if (slotAttempt > 0) {
      console.info(
        `[MetaApi][provision-investor] retry ${slotAttempt + 1}/${MAX_RESOURCE_SLOT_RETRIES} with resourceSlots=${resourceSlots}`,
      );
    }

    const response = await postProvisioningAccount(apiToken, transactionId, createBody);
    const result = await waitForProvisioningCreateResult(
      response,
      transactionId,
      apiToken,
      login,
      createBody,
    );

    if (result.success) {
      if (resourceSlots > 1) {
        console.info(
          `[MetaApi][provision-investor] account created with resourceSlots=${resourceSlots}`,
        );
      }
      return result;
    }

    const recommended = result.recommendedResourceSlots;
    if (
      result.isResourceSlotsError &&
      recommended != null &&
      recommended > resourceSlots &&
      slotAttempt < MAX_RESOURCE_SLOT_RETRIES - 1
    ) {
      console.warn(
        `[MetaApi][provision-investor] E_RESOURCE_SLOTS — MetaApi recommends ${recommended} slots (had ${resourceSlots})`,
      );
      resourceSlots = Math.min(recommended, MAX_RESOURCE_SLOTS);
      continue;
    }

    return result;
  }

  return {
    success: false,
    error:
      'MetaApi requires more resource slots for this broker account than we could allocate. Check MetaApi billing or contact support.',
  };
}

module.exports = {
  provisionInvestorMetaApiAccount,
  provisioningOptionsFromSiteSettings,
  resolveDefaultResourceSlots,
  buildProvisioningCreateBody,
  MAX_RESOURCE_SLOTS,
};
