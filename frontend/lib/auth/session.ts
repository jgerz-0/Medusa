import { fromBase64Url, toBase64Url } from './encoding';

const TOKEN_VERSION = 'v1';
const IV_LENGTH = 12; // 96-bit IV recommended for AES-GCM
const keyCache = new Map<string, Promise<CryptoKey>>();

function getCrypto(): Crypto {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error('Web Crypto API is not available in the current runtime.');
  }
  return globalThis.crypto as Crypto;
}

async function resolveKey(secret: string): Promise<CryptoKey> {
  let cached = keyCache.get(secret);
  if (!cached) {
    const cryptoApi = getCrypto();
    const encoder = new TextEncoder();
    const secretBytes = encoder.encode(secret);
    const digest = await cryptoApi.subtle.digest('SHA-256', secretBytes);
    cached = cryptoApi.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    keyCache.set(secret, cached);
  }
  return cached;
}

export async function encrypt<T>(payload: T, secret: string): Promise<string> {
  const cryptoApi = getCrypto();
  const key = await resolveKey(secret);
  const iv = cryptoApi.getRandomValues(new Uint8Array(IV_LENGTH));
  const encoder = new TextEncoder();
  const serialized = encoder.encode(JSON.stringify(payload));
  const ciphertext = await cryptoApi.subtle.encrypt({ name: 'AES-GCM', iv }, key, serialized);
  const bytes = new Uint8Array(ciphertext);
  return `${TOKEN_VERSION}.${toBase64Url(iv)}.${toBase64Url(bytes)}`;
}

export async function decrypt<T>(token: string, secret: string): Promise<T | null> {
  const [version, ivPart, dataPart] = token.split('.');
  if (version !== TOKEN_VERSION || !ivPart || !dataPart) {
    return null;
  }

  try {
    const cryptoApi = getCrypto();
    const key = await resolveKey(secret);
    const iv = fromBase64Url(ivPart);
    const data = fromBase64Url(dataPart);
    const plaintext = await cryptoApi.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    const decoder = new TextDecoder();
    const json = decoder.decode(new Uint8Array(plaintext));
    return JSON.parse(json) as T;
  } catch (error) {
    console.error('Failed to decrypt session payload', error);
    return null;
  }
}
