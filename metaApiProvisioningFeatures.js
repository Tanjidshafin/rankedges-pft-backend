/**
 * MetaApi provisioning: enable paid features (MetaStats) + deploy helpers.
 */

const crypto = require('crypto');

const PROVISIONING_BASE =
  process.env.META_API_PROVISIONING_BASE ||
  'https://mt-provisioning-api-v1.agiliumtrade.agiliumtrade.ai';

function provisioningTransactionId() {
  return crypto.randomBytes(16).toString('hex');
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function enableMetaStatsForAccount(metaApiAccountId, authToken) {
  const url = `${PROVISIONING_BASE}/users/current/accounts/${encodeURIComponent(metaApiAccountId)}/enable-metastats-api`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'auth-token': authToken,
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
  });
  let text = '';
  try {
    text = await res.text();
  } catch {
    text = '[read failed]';
  }

  console.log(
    `[MetaStats][provision][enable-metastats-api] HTTP ${res.status} account=${metaApiAccountId}`,
    text.length > 3000 ? `${text.slice(0, 3000)}…` : text,
  );

  return { ok: res.ok, status: res.status, text };
}

async function deployProvisioningAccount(metaApiAccountId, authToken) {
  const url = `${PROVISIONING_BASE}/users/current/accounts/${encodeURIComponent(metaApiAccountId)}/deploy`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'auth-token': authToken,
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'transaction-id': provisioningTransactionId(),
    },
  });
  let text = '';
  try {
    text = await res.text();
  } catch {
    text = '[read failed]';
  }

  console.log(
    `[MetaStats][provision][deploy] HTTP ${res.status} account=${metaApiAccountId}`,
    text.length > 2000 ? `${text.slice(0, 2000)}…` : text,
  );

  return { ok: res.ok || res.status === 202, status: res.status, text };
}

async function getProvisioningPayload(metaApiAccountId, authToken) {
  const url = `${PROVISIONING_BASE}/users/current/accounts/${encodeURIComponent(metaApiAccountId)}`;
  const res = await fetch(url, {
    headers: {
      'auth-token': authToken,
      Accept: 'application/json',
    },
  });
  if (!res.ok) {
    return null;
  }
  return res.json();
}

/**
 * @param {{ timeoutMs?: number; pollMs?: number }} opts
 */
async function waitForProvisioningDeployed(metaApiAccountId, authToken, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? Number(process.env.METAAPI_DEPLOY_POLL_MAX_MS || 300000);
  const pollMs = opts.pollMs ?? 3000;
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const data = await getProvisioningPayload(metaApiAccountId, authToken);
    if (data && typeof data === 'object') {
      const state = String(data.state || '').toUpperCase();
      console.log('[MetaStats][provision][poll]', metaApiAccountId, 'state=', state);
      if (state === 'DEPLOY_FAILED') {
        throw new Error(
          'MetaApi provisioning reported DEPLOY_FAILED after enabling MetaStats. Check MetaApi Cloud for credential or broker errors.',
        );
      }
      if (state === 'DEPLOYED') {
        return true;
      }
    }
    await delay(pollMs);
  }

  return false;
}

module.exports = {
  enableMetaStatsForAccount,
  deployProvisioningAccount,
  waitForProvisioningDeployed,
  provisioningTransactionId,
};
