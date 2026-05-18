const META_API_ACCOUNT_UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isMetaApiProvisioningAccountUuid(value) {
  return META_API_ACCOUNT_UUID_RE.test(String(value || '').trim());
}

function normalizeMetaApiProvisioningAccountId(value) {
  if (value === undefined || value === null) return null;
  const trimmed = String(value).trim();
  if (!trimmed) return null;
  return isMetaApiProvisioningAccountUuid(trimmed) ? trimmed : null;
}

function metaApiLoginVsUuidMessage(loginHint) {
  const loginPart = loginHint ? ` Your MT login is ${loginHint}.` : '';
  return (
    'MetaApi account id must be the UUID from MetaApi Cloud (not your MetaTrader login number).' +
    loginPart
  );
}

function assertMetaApiCloudAccountId(rawId, loginHint) {
  const normalized = normalizeMetaApiProvisioningAccountId(rawId);
  if (!normalized) {
    const hint =
      loginHint ||
      (/^\d+$/.test(String(rawId || '').trim()) ? String(rawId).trim() : undefined);
    throw new Error(metaApiLoginVsUuidMessage(hint));
  }
  return normalized;
}

module.exports = {
  isMetaApiProvisioningAccountUuid,
  normalizeMetaApiProvisioningAccountId,
  metaApiLoginVsUuidMessage,
  assertMetaApiCloudAccountId,
};
