const REDACTED = '[REDACTED]';

// Headers whose values contain sensitive user data
const SENSITIVE_HEADERS = new Set([
  'cookie',
  'set-cookie',
  'authorization',
  'proxy-authorization',
  'cf-connecting-ip',
  'x-real-ip',
  'x-forwarded-for',
  'cf-ray',
]);

// CF object keys that contain TLS fingerprinting or client auth data
const SENSITIVE_CF_KEYS = new Set([
  'tlsClientRandom',
  'tlsClientCiphersSha1',
  'tlsClientExtensionsSha1',
  'tlsClientExtensionsSha1Le',
  'tlsExportedAuthenticator',
  'tlsClientAuth',
  'tlsClientHelloLength',
]);

function redactHeaders(headers) {
  const result = {};
  for (const [key, value] of Object.entries(headers)) {
    result[key] = SENSITIVE_HEADERS.has(key) ? REDACTED : value;
  }
  return result;
}

function redactCf(cf) {
  if (!cf) return null;
  const result = {};
  for (const [key, value] of Object.entries(cf)) {
    result[key] = SENSITIVE_CF_KEYS.has(key) ? REDACTED : value;
  }
  return result;
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Collect headers
    const rawHeaders = {};
    for (const [key, value] of request.headers.entries()) {
      rawHeaders[key] = value;
    }

    // Collect query params
    const query = {};
    for (const [key, value] of url.searchParams.entries()) {
      query[key] = value;
    }

    // Read body (not available for GET/HEAD)
    let body = null;
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      try {
        body = await request.text();
      } catch {
        body = null;
      }
    }

    const echo = {
      method: request.method,
      url: request.url,
      path: url.pathname,
      query,
      headers: redactHeaders(rawHeaders),
      body: body || null,
      cf: redactCf(request.cf),
    };

    return new Response(JSON.stringify(echo, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    });
  },
};
