import {
  getOidcAudience,
  getOidcIssuer,
  getOidcRequestTimeoutSeconds,
  getOidcTokenSkewSeconds
} from './config';
import { decodeJson, fromBase64Url } from './encoding';
import { getOidcConfiguration } from './oidc';

interface CachedVerificationKey {
  alg: string;
  key: CryptoKey;
}

interface JwksCache {
  keys: Map<string, CachedVerificationKey>;
}

const DEFAULT_KEY_ID = '__default';
let cachedKeysPromise: Promise<JwksCache> | null = null;

function getCrypto(): Crypto {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error('Web Crypto API is unavailable in the current runtime.');
  }
  return globalThis.crypto as Crypto;
}

function sanitizeString(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function parseNumericClaim(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  if (typeof value === 'string' && value.trim().length > 0) {
    const parsed = Number.parseInt(value, 10);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return null;
}

function toAudienceArray(value: unknown): string[] {
  if (typeof value === 'string') {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.filter((entry): entry is string => typeof entry === 'string');
  }
  return [];
}

function selectKey(cache: JwksCache, kid?: string): CachedVerificationKey | undefined {
  if (kid && cache.keys.has(kid)) {
    return cache.keys.get(kid);
  }

  if (!kid) {
    if (cache.keys.size === 1) {
      return Array.from(cache.keys.values())[0];
    }
    return cache.keys.get(DEFAULT_KEY_ID);
  }

  return undefined;
}

async function importKeyFromJwk(entry: Record<string, unknown>): Promise<{
  id: string;
  key: CachedVerificationKey;
} | null> {
  if (!entry || typeof entry !== 'object') {
    return null;
  }

  const kty = sanitizeString(entry.kty);
  const n = sanitizeString(entry.n);
  const e = sanitizeString(entry.e);
  const alg = sanitizeString(entry.alg) ?? 'RS256';
  const kid = sanitizeString(entry.kid);

  if (kty !== 'RSA' || !n || !e || alg !== 'RS256') {
    return null;
  }

  const jwk: JsonWebKey = {
    kty: 'RSA',
    n,
    e,
    alg: 'RS256',
    use: sanitizeString(entry.use) ?? 'sig',
    kid,
    ext: true
  };

  try {
    const cryptoApi = getCrypto();
    const key = await cryptoApi.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256'
      },
      false,
      ['verify']
    );

    return {
      id: kid ?? DEFAULT_KEY_ID,
      key: { alg: 'RS256', key }
    };
  } catch (error) {
    console.error('Failed to import JWKS signing key', error);
    return null;
  }
}

async function fetchVerificationKeys(): Promise<JwksCache> {
  const { jwksUri } = await getOidcConfiguration();
  if (!jwksUri) {
    throw new Error('OIDC discovery document did not include a jwks_uri.');
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), getOidcRequestTimeoutSeconds() * 1000);

  try {
    const response = await fetch(jwksUri, {
      headers: { Accept: 'application/json' },
      signal: controller.signal
    });
    if (!response.ok) {
      throw new Error(`OIDC JWKS request failed with status ${response.status}.`);
    }

    const payload = (await response.json()) as { keys?: Record<string, unknown>[] };
    const entries = Array.isArray(payload.keys) ? payload.keys : [];

    const keys = new Map<string, CachedVerificationKey>();
    for (const entry of entries) {
      const imported = await importKeyFromJwk(entry);
      if (!imported) {
        continue;
      }

      // Preserve the first usable key as a default fallback for issuers that do not set kid.
      if (!keys.has(DEFAULT_KEY_ID)) {
        keys.set(DEFAULT_KEY_ID, imported.key);
      }

      keys.set(imported.id, imported.key);
    }

    if (keys.size === 0) {
      throw new Error('OIDC JWKS payload did not include usable RSA signing keys.');
    }

    return { keys } satisfies JwksCache;
  } finally {
    clearTimeout(timeout);
    controller.abort();
  }
}

async function resolveVerificationKey(kid?: string): Promise<CachedVerificationKey> {
  if (!cachedKeysPromise) {
    cachedKeysPromise = fetchVerificationKeys();
  }

  let cache = await cachedKeysPromise;
  let key = selectKey(cache, kid);

  if (!key) {
    cachedKeysPromise = fetchVerificationKeys();
    cache = await cachedKeysPromise;
    key = selectKey(cache, kid);
  }

  if (!key) {
    throw new Error(kid ? `Unknown signing key: ${kid}` : 'Unable to resolve signing key.');
  }

  return key;
}

function validateClaims(payload: Record<string, unknown>): void {
  const issuer = getOidcIssuer();
  if (payload.iss !== issuer) {
    throw new Error('Token issuer did not match the configured OIDC issuer.');
  }

  const expectedAudience = getOidcAudience();
  if (expectedAudience) {
    const audiences = toAudienceArray(payload.aud);
    if (!audiences.includes(expectedAudience)) {
      throw new Error('Token audience did not match the configured controller audience.');
    }
  }

  const skew = getOidcTokenSkewSeconds();
  const now = Math.floor(Date.now() / 1000);

  const expiration = parseNumericClaim(payload.exp);
  if (expiration !== null && now - skew > expiration) {
    throw new Error('Token is expired.');
  }

  const notBefore = parseNumericClaim(payload.nbf);
  if (notBefore !== null && now + skew < notBefore) {
    throw new Error('Token is not yet valid.');
  }

  const issuedAt = parseNumericClaim(payload.iat);
  if (issuedAt !== null && issuedAt - skew > now) {
    throw new Error('Token was issued in the future.');
  }
}

export async function validateBearerToken(token: string): Promise<Record<string, unknown>> {
  const normalized = token.trim();
  if (!normalized) {
    throw new Error('Bearer token is empty.');
  }

  const segments = normalized.split('.');
  if (segments.length !== 3) {
    throw new Error('Bearer token is not a well-formed JWT.');
  }

  const [encodedHeader, encodedPayload, encodedSignature] = segments;
  const header = decodeJson<Record<string, unknown>>(encodedHeader);

  const algorithm = sanitizeString(header?.alg) ?? '';
  if (algorithm !== 'RS256') {
    throw new Error(`Unsupported token algorithm: ${algorithm}`);
  }

  const kid = sanitizeString(header?.kid);
  const verificationKey = await resolveVerificationKey(kid);

  const encoder = new TextEncoder();
  const signedData = encoder.encode(`${encodedHeader}.${encodedPayload}`);
  const signature = fromBase64Url(encodedSignature);

  const cryptoApi = getCrypto();
  const valid = await cryptoApi.subtle.verify('RSASSA-PKCS1-v1_5', verificationKey.key, signature, signedData);
  if (!valid) {
    throw new Error('Token signature validation failed.');
  }

  const payload = decodeJson<Record<string, unknown>>(encodedPayload);
  validateClaims(payload);
  return payload;
}

export function clearCachedVerificationKeys(): void {
  cachedKeysPromise = null;
}
