/** @jest-environment node */

import { NextRequest, NextResponse } from 'next/server';

const originalEnv = process.env;
const originalFetch = global.fetch;

function setOidcEnv() {
  process.env = {
    ...originalEnv,
    MEDUSA_OIDC_ISSUER: 'https://idp.local/realms/medusa',
    MEDUSA_OIDC_CLIENT_ID: 'medusa-frontend',
    MEDUSA_OIDC_CLIENT_SECRET: 'super-secret',
    MEDUSA_SESSION_SECRET: 'session-secret-session-secret-session',
    MEDUSA_OIDC_SCOPES: 'openid profile email offline_access',
    MEDUSA_OIDC_REQUEST_TIMEOUT_SECONDS: '5',
    MEDUSA_OIDC_TOKEN_SKEW_SECONDS: '0',
    MEDUSA_SESSION_TTL_SECONDS: '3600'
  };
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
    const discovery = {
      issuer: 'https://idp.local/realms/medusa',
      authorization_endpoint: 'https://idp.local/realms/medusa/protocol/openid-connect/auth',
      token_endpoint: 'https://idp.local/realms/medusa/protocol/openid-connect/token',
      userinfo_endpoint: 'https://idp.local/realms/medusa/protocol/openid-connect/userinfo'
    };

    (global.fetch as jest.Mock).mockImplementation(async (input: RequestInfo) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.endsWith('/.well-known/openid-configuration')) {
        return new Response(JSON.stringify(discovery), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      throw new Error(`Unexpected fetch call to ${url}`);
    });

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
    const discovery = {
      issuer: 'https://idp.local/realms/medusa',
      authorization_endpoint: 'https://idp.local/realms/medusa/protocol/openid-connect/auth',
      token_endpoint: 'https://idp.local/realms/medusa/protocol/openid-connect/token',
      userinfo_endpoint: 'https://idp.local/realms/medusa/protocol/openid-connect/userinfo'
    };
    const tokenResponse = {
      access_token: 'access-token-1',
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
    };
    const userInfo = {
      sub: 'user-123',
      name: 'Analyst Example',
      email: 'analyst@example.com',
      roles: ['analyst']
    };

    (global.fetch as jest.Mock).mockImplementation(async (input: RequestInfo, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.endsWith('/.well-known/openid-configuration')) {
        return new Response(JSON.stringify(discovery), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      if (url === discovery.token_endpoint && init?.method === 'POST') {
        return new Response(JSON.stringify(tokenResponse), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      if (url === discovery.userinfo_endpoint) {
        return new Response(JSON.stringify(userInfo), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      throw new Error(`Unexpected fetch call to ${url}`);
    });

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
    expect(session?.accessToken).toBe(tokenResponse.access_token);
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
    const authLib = await import('@/lib/auth');
    const session = {
      subject: 'user-321',
      issuer: 'https://idp.local/realms/medusa',
      accessToken: 'token-valid',
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
  });

  it('refreshes an expiring session using the refresh token', async () => {
    const discovery = {
      issuer: 'https://idp.local/realms/medusa',
      authorization_endpoint: 'https://idp.local/realms/medusa/protocol/openid-connect/auth',
      token_endpoint: 'https://idp.local/realms/medusa/protocol/openid-connect/token',
      userinfo_endpoint: 'https://idp.local/realms/medusa/protocol/openid-connect/userinfo'
    };
    const refreshedTokens = {
      access_token: 'token-refreshed',
      refresh_token: 'refresh-token-2',
      expires_in: 7200
    };
    const userInfo = { sub: 'user-999', name: 'Refreshed User' };

    (global.fetch as jest.Mock).mockImplementation(async (input: RequestInfo, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.endsWith('/.well-known/openid-configuration')) {
        return new Response(JSON.stringify(discovery), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      if (url === discovery.token_endpoint && init?.method === 'POST') {
        return new Response(JSON.stringify(refreshedTokens), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      if (url === discovery.userinfo_endpoint) {
        return new Response(JSON.stringify(userInfo), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      throw new Error(`Unexpected fetch call to ${url}`);
    });

    const authLib = await import('@/lib/auth');
    const session = {
      subject: 'user-999',
      issuer: 'https://idp.local/realms/medusa',
      accessToken: 'token-expired',
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
    const refreshedCookie = response?.cookies.get(authLib.getSessionCookieName());
    expect(refreshedCookie?.value).toBeDefined();
    const refreshedSession = await authLib.readSession({
      get: (name: string) => (name === authLib.getSessionCookieName() ? refreshedCookie : undefined)
    });
    expect(refreshedSession?.accessToken).toBe('token-refreshed');
  });

  it('returns 401 for API routes without credentials', async () => {
    const { middleware } = await import('@/middleware');
    const request = new NextRequest('http://dashboard.local/api/findings');
    const response = await middleware(request);
    expect(response.status).toBe(401);
  });

  it('redirects GET requests to the login endpoint when unauthenticated', async () => {
    const { middleware } = await import('@/middleware');
    const request = new NextRequest('http://dashboard.local/findings');
    const response = await middleware(request);
    expect(response.status).toBe(307);
    expect(response.headers.get('location')).toContain('/api/auth/login');
  });

  it('permits static API key access for automation headers', async () => {
    process.env.CONTROLLER_API_KEY = 'static-key';
    const { middleware } = await import('@/middleware');
    const request = new NextRequest('http://dashboard.local/reports', {
      headers: {
        authorization: 'Bearer static-key'
      }
    });
    const response = await middleware(request);
    expect(response?.status ?? 200).toBe(200);
  });
});
