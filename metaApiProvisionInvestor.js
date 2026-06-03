/**
 * Server-side MetaApi investor-password provisioning (uses site METAAPI token; never exposed to the browser).
 */
const crypto = require('crypto');
const { formatMetaApiHttpError } = require('./metaApiHttpErrors');
const {
  normalizeMetaApiProvisioningAccountId,
  metaApiLoginVsUuidMessage,
} = require('./metaApiProvisioningId');

const PROVISIONING_API_BASE =
  process.env.META_API_PROVISIONING_BASE ||
  'https://mt-provisioning-api-v1.agiliumtrade.agiliumtrade.ai';

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

async function waitForProvisioningCreateResult(
  initialResponse,
  transactionId,
  apiToken,
  login,
  password,
  server,
  platform,
  reliability,
  cloudType,
  provisioningRegion,
) {
  const createBody = {
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
    metastatsApiEnabled: true,
  };
  const createHeaders = {
    'auth-token': apiToken,
    'Content-Type': 'application/json',
    'transaction-id': transactionId,
  };

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
      response = await fetch(`${PROVISIONING_API_BASE}/users/current/accounts`, {
        method: 'POST',
        headers: createHeaders,
        body: JSON.stringify(createBody),
      });
      continue;
    }

    if (!response.ok) {
      const message = await formatMetaApiHttpError('provision-investor-account', response);
      return { success: false, error: message };
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
        region: typeof data.region === 'string' && data.region.trim() ? data.region : provisioningRegion,
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
  const transactionId = provisioningTransactionId();

  const response = await fetch(`${PROVISIONING_API_BASE}/users/current/accounts`, {
    method: 'POST',
    headers: {
      'auth-token': apiToken,
      'Content-Type': 'application/json',
      'transaction-id': transactionId,
    },
    body: JSON.stringify({
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
      metastatsApiEnabled: true,
    }),
  });

  return waitForProvisioningCreateResult(
    response,
    transactionId,
    apiToken,
    login,
    password,
    server,
    platform,
    reliability,
    cloudType,
    provisioningRegion,
  );
}

module.exports = { provisionInvestorMetaApiAccount, provisioningOptionsFromSiteSettings };
