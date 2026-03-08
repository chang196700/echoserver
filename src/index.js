const REDACTED = '[REDACTED]';

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

// --- TOTP implementation using Web Crypto API ---

function base32Decode(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const str = base32.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  const bytes = [];
  let bits = 0;
  let value = 0;
  for (const char of str) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

async function computeTotp(secretBytes, period, time) {
  const counter = Math.floor(time / period);
  const counterBuffer = new ArrayBuffer(8);
  const view = new DataView(counterBuffer);
  view.setUint32(0, 0, false);
  view.setUint32(4, counter, false);

  const key = await crypto.subtle.importKey(
    'raw', secretBytes,
    { name: 'HMAC', hash: 'SHA-1' },
    false, ['sign']
  );
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBuffer));

  const offset = sig[19] & 0xf;
  const code = (
    ((sig[offset]     & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) <<  8) |
     (sig[offset + 3] & 0xff)
  ) % 1000000;

  return code.toString().padStart(6, '0');
}

function parseTotpUri(uri) {
  const url = new URL(uri);
  const secret = url.searchParams.get('secret');
  const period = parseInt(url.searchParams.get('period') || '30', 10);
  return { secret, period };
}

async function verifyTotp(authHeader, totpUri) {
  if (!authHeader || !authHeader.toLowerCase().startsWith('totp ')) return false;
  const code = authHeader.slice(5).trim();
  const { secret, period } = parseTotpUri(totpUri);
  const secretBytes = base32Decode(secret);
  const now = Math.floor(Date.now() / 1000);
  // Allow ±1 window to account for clock skew
  for (const delta of [-1, 0, 1]) {
    const expected = await computeTotp(secretBytes, period, now + delta * period);
    if (expected === code) return true;
  }
  return false;
}

// --- Worker entry point ---

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const rawHeaders = {};
    for (const [key, value] of request.headers.entries()) {
      rawHeaders[key] = value;
    }

    const query = {};
    for (const [key, value] of url.searchParams.entries()) {
      query[key] = value;
    }

    let body = null;
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      try {
        body = await request.text();
      } catch {
        body = null;
      }
    }

    // Determine whether to show sensitive fields
    const totpUri = env.TOTP_URI || null;
    let authenticated = false;
    if (totpUri) {
      authenticated = await verifyTotp(rawHeaders['authorization'] || '', totpUri);
    }

    const echo = {
      method: request.method,
      url: request.url,
      path: url.pathname,
      query,
      headers: authenticated ? rawHeaders : redactHeaders(rawHeaders),
      body: body || null,
      cf: authenticated ? (request.cf || null) : redactCf(request.cf),
      auth: totpUri ? (authenticated ? 'authenticated' : 'unauthenticated') : 'disabled',
    };

    return new Response(JSON.stringify(echo, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    });
  },
};
