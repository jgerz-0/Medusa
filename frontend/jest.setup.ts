import '@testing-library/jest-dom';

if (!globalThis.crypto || !globalThis.crypto.subtle) {
  // Provide Node's Web Crypto implementation for tests running in jsdom.
  const { webcrypto } = require('crypto');
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    configurable: true
  });
}
