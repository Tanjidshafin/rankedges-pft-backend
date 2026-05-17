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

/**
 * @param {string} operation label, e.g. "account-information" or "history-deals"
 * @param {globalThis.Response} response failed fetch response (body unread)
 * @param {Record<string, string | undefined>} [extra] optional region, accountId for operators
 */
async function formatMetaApiHttpError(operation, response, extra = {}) {
  const status = response.status;
  const statusText = (response.statusText || '').trim();

  let extracted = '';
  try {
    const raw = await response.text();
    if (raw && raw.trim()) {
      const trimmed = raw.trim();
      if (/^<[a-z!]/i.test(trimmed)) {
        extracted = '';
      } else {
        try {
          const parsed = JSON.parse(trimmed);
          const chunks = [];
          if (parsed.id != null && String(parsed.id)) chunks.push(String(parsed.id));
          if (parsed.error != null && String(parsed.error) !== String(parsed.message)) {
            chunks.push(String(parsed.error));
          }
          if (parsed.message) chunks.push(String(parsed.message));
          if (parsed.details) chunks.push(String(parsed.details));
          if (parsed.description) chunks.push(String(parsed.description));
          if (typeof parsed.numericCode === 'number') chunks.push(`numericCode=${parsed.numericCode}`);
          extracted = chunks.length ? [...new Set(chunks)].join(' — ') : '';
          if (!extracted) extracted = truncate(trimmed);
        } catch {
          extracted = truncate(trimmed);
        }
      }
    }
  } catch {
    /* ignore body read failures */
  }

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

  let joined = parts.filter(Boolean).join(' ');
  const lowered = joined.toLowerCase();
  if (/top\s*[- ]?up|high\s+reliability/.test(lowered)) {
    joined +=
      ' This comes from MetaApi billing/quota — add credits or upgrade your MetaApi subscription (https://app.metaapi.cloud).';
  }
  if (/does\s+not\s+match\s+the\s+account\s+region|\/api-access\/api-urls/.test(lowered)) {
    joined +=
      ' Confirm the broker terminal is connected in MetaApi and that you use this account’s hosted region URL (MetaApi dashboard → API access → API URLs).';
  }

  return joined;
}

module.exports = { formatMetaApiHttpError };
