const BASE64_PADDING = /=+$/;

function hasBuffer(): boolean {
  return typeof Buffer !== 'undefined';
}

export function toBase64Url(data: Uint8Array): string {
  if (hasBuffer()) {
    return Buffer.from(data).toString('base64url');
  }

  let binary = '';
  for (const byte of data) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(BASE64_PADDING, '');
}

export function fromBase64Url(value: string): Uint8Array {
  let base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const paddingNeeded = base64.length % 4;
  if (paddingNeeded > 0) {
    base64 = base64.padEnd(base64.length + (4 - paddingNeeded), '=');
  }

  if (hasBuffer()) {
    return new Uint8Array(Buffer.from(base64, 'base64'));
  }

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function decodeJson<T>(payload: string): T {
  const bytes = fromBase64Url(payload);
  const decoder = new TextDecoder();
  const json = decoder.decode(bytes);
  return JSON.parse(json) as T;
}

export function encodeJson(value: unknown): string {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(JSON.stringify(value));
  return toBase64Url(bytes);
}
