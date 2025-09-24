/** @jest-environment node */

import { createPublicKey, createSign, generateKeyPairSync } from 'crypto';
import { NextRequest, NextResponse } from 'next/server';
import type { MedusaSession } from '@/lib/auth';

const originalEnv = process.env;
const originalFetch = global.fetch;

const issuer = 'https://idp.local/realms/medusa';
const authorizationEndpoint = `${issuer}/protocol/openid-connect/auth`;
const tokenEndpoint = `${issuer}/protocol/openid-connect/token`;
const userinfoEndpoint = `${issuer}/protocol/openid-connect/userinfo`;
const jwksUri = `${issuer}/protocol/openid-connect/certs`;

let privateKeyPem: string;
let publicJwk: JsonWebKey;

beforeAll(() => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  privateKeyPem = privateKey;
  const exported = createPublicKey(publicKey).export({ format: 'jwk' }) as JsonWebKey;
  exported.kid = 'test-key';
  exported.use = 'sig';
  exported.alg = 'RS256';
  publicJwk = exported;
});

function setOidcEnv() {
  process.env = {
    ...originalEnv,
    MEDUSA_OIDC_ISSUER: issuer,
    MEDUSA_OIDC_CLIENT_ID: 'medusa-frontend',
    MEDUSA_OIDC_CLIENT_SECRET: 'super-secret',
    MEDUSA_OIDC_AUDIENCE: 'medusa-controller',
    MEDUSA_SESSION_SECRET: 'session-secret-session-secret-session',
    MEDUSA_OIDC_SCOPES: 'openid profile email offline_access',
    MEDUSA_OIDC_REQUEST_TIMEOUT_SECONDS: '5',
    MEDUSA_OIDC_TOKEN_SKEW_SECONDS: '0',
    MEDUSA_SESSION_TTL_SECONDS: '3600'
  };
}

function toUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') {
    return input;
  }
  if (input instanceof URL) {
    return input.toString();
  }
  return input.url;
}

interface OidcMockOptions {
  tokenResponse?: Record<string, unknown>;
  userInfoResponse?: Record<string, unknown>;
}

function setupOidcFetch(options: OidcMockOptions = {}) {
  const discovery = {
    issuer,
    authorization_endpoint: authorizationEndpoint,
    token_endpoint: tokenEndpoint,
    userinfo_endpoint: userinfoEndpoint,
    jwks_uri: jwksUri
  };

  (global.fetch as jest.Mock).mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = toUrl(input);

    if (url.endsWith('/.well-known/openid-configuration')) {
      return new Response(JSON.stringify(discovery), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (url === jwksUri) {
      return new Response(JSON.stringify({ keys: [publicJwk] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (options.tokenResponse && url === tokenEndpoint && init?.method === 'POST') {
      return new Response(JSON.stringify(options.tokenResponse), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (options.userInfoResponse && url === userinfoEndpoint) {
      return new Response(JSON.stringify(options.userInfoResponse), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    throw new Error(`Unexpected fetch call to ${url}`);
  });

  return discovery;
}

interface AccessTokenOptions {
  subject?: string;
  expiresInSeconds?: number;
  issuedAt?: number;
  claims?: Record<string, unknown>;
}

function createSignedAccessToken(options: AccessTokenOptions = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const issuedAt = options.issuedAt ?? now;
  const expiresInSeconds = options.expiresInSeconds ?? 3600;
  const payload = {
    iss: issuer,
    aud: process.env.MEDUSA_OIDC_AUDIENCE ?? 'medusa-controller',
    sub: options.subject ?? 'user-123',
    iat: issuedAt,
    exp: issuedAt + expiresInSeconds,
    ...(options.claims ?? {})
  } satisfies Record<string, unknown>;

  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid: publicJwk.kid
  } satisfies Record<string, unknown>;

  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signer = createSign('RSA-SHA256');
  signer.update(`${encodedHeader}.${encodedPayload}`);
  signer.end();
  const signature = signer.sign(privateKeyPem, 'base64url');
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

describe('OIDC login flow', () => {
  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
    setOidcEnv();
    global.fetch = jest.fn() as unknown as typeof fetch;
  });

  afterEach(() => {
    process.env = originalEnv;
    global.fetch = originalFetch;
  });

  it('redirects to the identity provider and persists the authorization state', async () => {
    const discovery = setupOidcFetch();

    const loginRoute = await import('@/app/api/auth/login/route');
    const authLib = await import('@/lib/auth');
    const request = new NextRequest('http://dashboard.local/api/auth/login');
    const response = await loginRoute.GET(request);

    expect(response.status).toBe(307);
    const location = response.headers.get('location');
    expect(location).toContain(discovery.authorization_endpoint);

    const stateCookie = response.cookies.get(authLib.getStateCookieName());
    expect(stateCookie?.value).toBeDefined();

    const state = await authLib.readAuthorizationState(response.cookies);
    expect(state).not.toBeNull();
    expect(state?.codeVerifier.length ?? 0).toBeGreaterThan(0);
  });

  it('completes the authorization code callback and stores the session cookie', async () => {
    const accessToken = createSignedAccessToken({ subject: 'user-123' });
    const tokenResponse = {
      access_token: accessToken,
      refresh_token: 'refresh-token-1',
      expires_in: 3600,
      id_token:
        'header.' +
        Buffer.from(
          JSON.stringify({
            sub: 'user-123',
            name: 'Analyst Example',
            email: 'analyst@example.com'
          })
        ).toString('base64url') +
        '.signature'
    } satisfies Record<string, unknown>;
    const userInfo = {
      sub: 'user-123',
      name: 'Analyst Example',
      email: 'analyst@example.com',
      roles: ['analyst']
    } satisfies Record<string, unknown>;

    setupOidcFetch({ tokenResponse, userInfoResponse: userInfo });

    const loginRoute = await import('@/app/api/auth/login/route');
    const callbackRoute = await import('@/app/api/auth/callback/route');
    const authLib = await import('@/lib/auth');

    const loginRequest = new NextRequest('http://dashboard.local/api/auth/login');
    const loginResponse = await loginRoute.GET(loginRequest);

    const stateCookie = loginResponse.cookies.get(authLib.getStateCookieName());
    expect(stateCookie?.value).toBeDefined();
    const state = await authLib.readAuthorizationState(loginResponse.cookies);
    expect(state).not.toBeNull();

    const callbackUrl = new URL('http://dashboard.local/api/auth/callback');
    callbackUrl.searchParams.set('code', 'auth-code-123');
    callbackUrl.searchParams.set('state', state!.state);

    const callbackRequest = new NextRequest(callbackUrl.toString(), {
      headers: {
        cookie: `${authLib.getStateCookieName()}=${stateCookie?.value}`
      }
    });

    const callbackResponse = await callbackRoute.GET(callbackRequest);
    expect(callbackResponse.status).toBe(307);
    expect(callbackResponse.headers.get('location')).toBe('http://dashboard.local/');

    const sessionCookie = callbackResponse.cookies.get(authLib.getSessionCookieName());
    expect(sessionCookie?.value).toBeDefined();
    const session = await authLib.readSession({
      get: (name: string) => (name === authLib.getSessionCookieName() ? sessionCookie : undefined)
    });
    expect(session?.subject).toBe('user-123');
    expect(session?.email).toBe('analyst@example.com');
    expect(session?.accessToken).toBe(accessToken);
  });
});

describe('middleware session enforcement', () => {
  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
    setOidcEnv();
    global.fetch = jest.fn() as unknown as typeof fetch;
  });

  afterEach(() => {
    process.env = originalEnv;
    global.fetch = originalFetch;
  });

  it('allows requests when a valid session cookie is present', async () => {
    setupOidcFetch();
    const authLib = await import('@/lib/auth');
    const accessToken = createSignedAccessToken({ subject: 'user-321' });
    const session: MedusaSession = {
      subject: 'user-321',
      issuer,
      accessToken,
      tokenType: 'Bearer',
      accessTokenExpiresAt: Date.now() + 10 * 60 * 1000,
      issuedAt: Date.now()
    };
    const bootstrap = NextResponse.next();
    await authLib.persistSession(bootstrap, session);
    const cookie = bootstrap.cookies.get(authLib.getSessionCookieName());
    expect(cookie?.value).toBeDefined();

    const request = new NextRequest('http://dashboard.local/findings', {
      headers: {
        cookie: `${authLib.getSessionCookieName()}=${cookie?.value}`
      }
    });

    const { middleware } = await import('@/middleware');
    const response = await middleware(request);
    expect(response?.status ?? 200).toBe(200);
    expect(response?.headers.get('x-middleware-request-authorization')).toBe(`Bearer ${accessToken}`);
    expect(response?.headers.get('Cache-Control')).toBe('no-store');
  });

  it('refreshes an expiring session using the refresh token', async () => {
    const refreshedToken = createSignedAccessToken({ subject: 'user-999', expiresInSeconds: 7200 });
    const refreshedTokens = {
      access_token: refreshedToken,
      refresh_token: 'refresh-token-2',
      expires_in: 7200
    } satisfies Record<string, unknown>;
    const userInfo = { sub: 'user-999', name: 'Refreshed User' } satisfies Record<string, unknown>;

    setupOidcFetch({ tokenResponse: refreshedTokens, userInfoResponse: userInfo });

    const authLib = await import('@/lib/auth');
    const expiredToken = createSignedAccessToken({
      subject: 'user-999',
      expiresInSeconds: -60,
      issuedAt: Math.floor(Date.now() / 1000) - 3600
    });
    const session: MedusaSession = {
      subject: 'user-999',
      issuer,
      accessToken: expiredToken,
      refreshToken: 'refresh-token-1',
      tokenType: 'Bearer',
      accessTokenExpiresAt: Date.now() - 30 * 1000,
      issuedAt: Date.now() - 3600 * 1000
    };
    const bootstrap = NextResponse.next();
    await authLib.persistSession(bootstrap, session);
    const cookie = bootstrap.cookies.get(authLib.getSessionCookieName());

    const request = new NextRequest('http://dashboard.local', {
      headers: {
        cookie: `${authLib.getSessionCookieName()}=${cookie?.value}`
      }
    });

    const { middleware } = await import('@/middleware');
    const response = await middleware(request);
    expect(response?.status ?? 200).toBe(200);
    expect(response?.headers.get('x-middleware-request-authorization')).toBe(`Bearer ${refreshedToken}`);
    const refreshedCookie = response?.cookies.get(authLib.getSessionCookieName());
    expect(refreshedCookie?.value).toBeDefined();
    const refreshedSession = await authLib.readSession({
      get: (name: string) => (name === authLib.getSessionCookieName() ? refreshedCookie : undefined)
    });
    expect(refreshedSession?.accessToken).toBe(refreshedToken);
  });

  it('returns 401 for API routes without credentials', async () => {
    setupOidcFetch();
    const { middleware } = await import('@/middleware');
    const request = new NextRequest('http://dashboard.local/api/findings');
    const response = await middleware(request);
    expect(response.status).toBe(401);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
  });

  it('redirects GET requests to the login endpoint when unauthenticated', async () => {
    setupOidcFetch();
    const { middleware } = await import('@/middleware');
    const request = new NextRequest('http://dashboard.local/findings');
    const response = await middleware(request);
    expect(response.status).toBe(307);
    expect(response.headers.get('location')).toContain('/api/auth/login');
    expect(response.headers.get('Cache-Control')).toBe('no-store');
  });

  it('permits static API key access for automation headers', async () => {
    setupOidcFetch();
    process.env.CONTROLLER_API_KEY = 'static-key';
    const { middleware } = await import('@/middleware');
    const request = new NextRequest('http://dashboard.local/reports', {
      headers: {
        authorization: 'Bearer static-key'
      }
    });
    const response = await middleware(request);
    expect(response?.status ?? 200).toBe(200);
    expect(response?.headers.get('x-middleware-request-authorization')).toBe('Bearer static-key');
    expect(response?.headers.get('x-middleware-request-x-api-key')).toBe('static-key');
  });
});
