/**
 * Builds human-readable MetaApi failures for API responses where body was not OK.
 * Consumes the response body (call only on error branches).
 */

const MAX_BODY_SNIPPET = 800;

/** Short guidance when MetaApi/upstream omits JSON details (common with 504/HTML gateways). */
const HTTP_HINTS = {
  400: 'Bad request — MetaApi rejected the payload or parameters.',
  401: 'Unauthorized — check MetaApi auth token permissions for this account.',
  402: 'Payment required — MetaApi quota/credits depleted; top up or upgrade in MetaApi billing.',
  404: 'Not found — account id may be wrong or removed in MetaApi.',
  408: 'Request timeout — MetaApi did not respond in time.',
  429: 'Rate limited — space out retries or upgrade MetaApi throughput.',
  500: 'MetaApi returned an internal error — retry later.',
  502: 'Bad gateway — an intermediary failed between this server and MetaApi.',
  503: 'Service unavailable — MetaApi may be overloaded or under maintenance.',
  504:
    'Gateway timeout — MetaApi or the broker terminal took too long. This endpoint uses refreshTerminalState=true, which is slow; retry in 1–2 minutes or sync when terminals are quieter.',
};

function truncate(s, n = MAX_BODY_SNIPPET) {
  const t = String(s).trim();
  if (!t.length) return '';
  if (t.length <= n) return t;
  return `${t.slice(0, n)}…`;
}

function formatErrorDetails(details) {
  if (details == null) return '';
  if (typeof details === 'string') return details;
  if (typeof details !== 'object') return String(details);

  const parts = [];
  if (details.code != null && String(details.code).trim()) {
    parts.push(String(details.code));
  }
  const recommended =
    details.recommendedResourceSlots ?? details.recommended_resource_slots;
  if (recommended != null && Number.isFinite(Number(recommended))) {
    parts.push(`recommendedResourceSlots=${Math.trunc(Number(recommended))}`);
  }
  if (parts.length) return parts.join(', ');

  try {
    return truncate(JSON.stringify(details));
  } catch {
    return '';
  }
}

function extractRecommendedResourceSlots(parsed) {
  if (!parsed || typeof parsed !== 'object') return null;
  const details = parsed.details;
  if (!details || typeof details !== 'object') return null;
  const raw = details.recommendedResourceSlots ?? details.recommended_resource_slots;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 1) return null;
  return Math.trunc(n);
}

function isResourceSlotsProvisioningError(status, parsed) {
  if (status !== 400 || !parsed || typeof parsed !== 'object') return false;
  const details = parsed.details;
  if (details && typeof details === 'object' && details.code === 'E_RESOURCE_SLOTS') {
    return true;
  }
  const haystack = `${parsed.message || ''} ${parsed.error || ''}`.toLowerCase();
  return haystack.includes('resource slots');
}

function extractMessageFromParsed(parsed, rawText) {
  if (!parsed || typeof parsed !== 'object') {
    return truncate(rawText || '');
  }

  const chunks = [];
  if (parsed.id != null && String(parsed.id)) chunks.push(String(parsed.id));
  if (parsed.error != null && String(parsed.error) !== String(parsed.message)) {
    chunks.push(String(parsed.error));
  }
  if (parsed.message) chunks.push(String(parsed.message));
  const detailsText = formatErrorDetails(parsed.details);
  if (detailsText) chunks.push(detailsText);
  if (parsed.description) chunks.push(String(parsed.description));
  if (typeof parsed.numericCode === 'number') chunks.push(`numericCode=${parsed.numericCode}`);

  const unique = [...new Set(chunks.filter(Boolean))];
  if (unique.length) return unique.join(' — ');
  return truncate(rawText || '');
}

function appendMetaApiHints(joined) {
  let result = joined;
  const lowered = result.toLowerCase();

  if (/top\s*[- ]?up|high\s+reliability/.test(lowered)) {
    result +=
      ' This comes from MetaApi billing/quota — add credits or upgrade your MetaApi subscription (https://app.metaapi.cloud).';
  }
  if (/does\s+not\s+match\s+the\s+account\s+region|\/api-access\/api-urls/.test(lowered)) {
    result +=
      ' Confirm the broker terminal is connected in MetaApi and that you use this account’s hosted region URL (MetaApi dashboard → API access → API URLs).';
  }
  if (/resource slots|e_resource_slots/.test(lowered)) {
    result +=
      ' MetaApi requires extra resource slots for this broker account (paid MetaApi option). The server retries automatically when MetaApi returns a recommended slot count.';
  }

  return result;
}

/**
 * @param {string} operation
 * @param {number} status
 * @param {unknown} parsed
 * @param {string} rawText
 * @param {Record<string, string | undefined>} [extra]
 */
function formatMetaApiHttpErrorFromBody(operation, status, statusText, parsed, rawText, extra = {}) {
  const extracted = extractMessageFromParsed(parsed, rawText);
  const parts = [`MetaApi ${operation} failed (HTTP ${status}${statusText ? ` ${statusText}` : ''}).`];

  if (extracted) {
    parts.push(extracted.endsWith('.') ? extracted : `${extracted}.`);
  }

  const hint = HTTP_HINTS[status];
  if (hint && (!extracted || status === 504)) {
    parts.push(hint);
  }

  if (extra.region) parts.push(`[region: ${extra.region}]`);
  if (extra.accountId) parts.push(`[MetaApi account: ${extra.accountId}]`);

  return appendMetaApiHints(parts.filter(Boolean).join(' '));
}

/**
 * @param {string} operation label, e.g. "account-information" or "history-deals"
 * @param {globalThis.Response} response failed fetch response (body unread)
 * @param {Record<string, string | undefined>} [extra] optional region, accountId for operators
 */
async function formatMetaApiHttpError(operation, response, extra = {}) {
  const status = response.status;
  const statusText = (response.statusText || '').trim();

  let rawText = '';
  let parsed = null;

  try {
    rawText = await response.text();
    if (rawText && rawText.trim() && !/^<[a-z!]/i.test(rawText.trim())) {
      try {
        parsed = JSON.parse(rawText.trim());
      } catch {
        parsed = null;
      }
    }
  } catch {
    /* ignore body read failures */
  }

  return formatMetaApiHttpErrorFromBody(operation, status, statusText, parsed, rawText, extra);
}

module.exports = {
  formatMetaApiHttpError,
  formatMetaApiHttpErrorFromBody,
  formatErrorDetails,
  extractRecommendedResourceSlots,
  isResourceSlotsProvisioningError,
  extractMessageFromParsed,
};
