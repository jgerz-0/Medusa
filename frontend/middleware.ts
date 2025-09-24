import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { controllerApiKey } from '@/lib/config';
import {
  clearSession,
  isAccessTokenExpired,
  persistSession,
  readSession,
  refreshSession,
  validateBearerToken
} from '@/lib/auth';
import type { MedusaSession } from '@/lib/auth';

const textEncoder = new TextEncoder();

function isApiRoute(pathname: string): boolean {
  return pathname.startsWith('/api/');
}

function withNoStore<T extends NextResponse>(response: T): T {
  response.headers.set('Cache-Control', 'no-store');
  return response;
}

function buildLoginRedirect(request: NextRequest): NextResponse {
  const loginUrl = new URL('/api/auth/login', request.nextUrl.origin);
  if (request.method === 'GET') {
    const returnTo = `${request.nextUrl.pathname}${request.nextUrl.search}`;
    loginUrl.searchParams.set('returnTo', returnTo);
  }
  return withNoStore(NextResponse.redirect(loginUrl));
}

function sanitizeBearer(value: string | null): string | null {
  if (!value) {
    return null;
  }
  const normalized = value.trim();
  if (!normalized) {
    return null;
  }
  if (!normalized.toLowerCase().startsWith('bearer ')) {
    return null;
  }
  const token = normalized.slice(7).trim();
  return token.length > 0 ? token : null;
}

function sanitizeApiKey(value: string | null): string | null {
  if (!value) {
    return null;
  }
  const normalized = value.trim();
  return normalized.length > 0 ? normalized : null;
}

function constantTimeEquals(left: string | null, right: string | null | undefined): boolean {
  if (!left || !right) {
    return false;
  }

  const leftBytes = textEncoder.encode(left);
  const rightBytes = textEncoder.encode(right);
  if (leftBytes.length !== rightBytes.length) {
    return false;
  }

  let mismatch = 0;
  for (let index = 0; index < leftBytes.length; index += 1) {
    mismatch |= leftBytes[index]! ^ rightBytes[index]!;
  }

  return mismatch === 0;
}

function buildAuthorizedResponse(request: NextRequest, headers: Headers): NextResponse {
  return withNoStore(NextResponse.next({ request: { headers } }));
}

async function authorizeSession(request: NextRequest, session: MedusaSession): Promise<NextResponse> {
  let active = session;
  let refreshed = false;

  if (isAccessTokenExpired(active)) {
    const replacement = await refreshSession(active);
    if (!replacement) {
      const response = buildLoginRedirect(request);
      clearSession(response);
      return response;
    }
    active = replacement;
    refreshed = true;
  }

  try {
    await validateBearerToken(active.accessToken);
  } catch (error) {
    console.warn('Session bearer token failed validation', error);
    const response = buildLoginRedirect(request);
    clearSession(response);
    return response;
  }

  const headers = new Headers(request.headers);
  const tokenType = active.tokenType?.trim() ?? 'Bearer';
  headers.set('authorization', `${tokenType} ${active.accessToken}`);

  const response = buildAuthorizedResponse(request, headers);
  if (refreshed) {
    await persistSession(response, active);
  }
  return response;
}

function authorizeApiKey(request: NextRequest, apiKey: string): NextResponse {
  const headers = new Headers(request.headers);
  headers.set('x-api-key', apiKey);
  if (!headers.get('authorization')) {
    headers.set('authorization', `Bearer ${apiKey}`);
  }
  return buildAuthorizedResponse(request, headers);
}

async function authorizeBearerHeader(request: NextRequest, token: string): Promise<NextResponse | null> {
  if (controllerApiKey && constantTimeEquals(token, controllerApiKey)) {
    return authorizeApiKey(request, token);
  }

  try {
    await validateBearerToken(token);
    const headers = new Headers(request.headers);
    headers.set('authorization', `Bearer ${token}`);
    return buildAuthorizedResponse(request, headers);
  } catch (error) {
    console.warn('Bearer token validation failed', error);
    return null;
  }
}

export async function middleware(request: NextRequest) {
  try {
    const session = await readSession(request.cookies);
    if (session) {
      return await authorizeSession(request, session);
    }
  } catch (error) {
    console.error('Failed to resolve session cookie', error);
  }

  const bearerToken = sanitizeBearer(request.headers.get('authorization'));
  if (bearerToken) {
    const result = await authorizeBearerHeader(request, bearerToken);
    if (result) {
      return result;
    }
  }

  const apiKeyHeader = sanitizeApiKey(request.headers.get('x-api-key'));
  if (apiKeyHeader && controllerApiKey && constantTimeEquals(apiKeyHeader, controllerApiKey)) {
    return authorizeApiKey(request, apiKeyHeader);
  }

  if (isApiRoute(request.nextUrl.pathname) || request.method !== 'GET') {
    return withNoStore(NextResponse.json({ error: 'unauthorized' }, { status: 401 }));
  }

  return buildLoginRedirect(request);
}

export const config = {
  matcher: ['/((?!_next|favicon.ico|api/auth|api/health).*)']
};
