import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { controllerApiKey, controllerJwt } from '@/lib/config';
import {
  clearSession,
  isAccessTokenExpired,
  persistSession,
  readSession,
  refreshSession
} from '@/lib/auth';

function matchesStaticToken(value: string | null, token: string | undefined): boolean {
  if (!value || !token) {
    return false;
  }
  const normalized = value.trim();
  if (!normalized) {
    return false;
  }
  if (normalized.toLowerCase().startsWith('bearer ')) {
    return normalized.slice(7).trim() === token;
  }
  return normalized === token;
}

function hasStaticCredential(request: NextRequest): boolean {
  const authHeader = request.headers.get('authorization');
  const apiKeyHeader = request.headers.get('x-api-key');
  return (
    matchesStaticToken(authHeader, controllerApiKey) ||
    matchesStaticToken(authHeader, controllerJwt) ||
    matchesStaticToken(apiKeyHeader, controllerApiKey)
  );
}

function isApiRoute(pathname: string): boolean {
  return pathname.startsWith('/api/');
}

function buildLoginRedirect(request: NextRequest): NextResponse {
  const loginUrl = new URL('/api/auth/login', request.nextUrl.origin);
  if (request.method === 'GET') {
    const returnTo = `${request.nextUrl.pathname}${request.nextUrl.search}`;
    loginUrl.searchParams.set('returnTo', returnTo);
  }
  return NextResponse.redirect(loginUrl);
}

export async function middleware(request: NextRequest) {
  try {
    const session = await readSession(request.cookies);
    if (session) {
      if (!isAccessTokenExpired(session)) {
        return NextResponse.next();
      }

      const refreshed = await refreshSession(session);
      if (refreshed) {
        const response = NextResponse.next();
        await persistSession(response, refreshed);
        return response;
      }

      const response = buildLoginRedirect(request);
      clearSession(response);
      return response;
    }
  } catch (error) {
    console.error('Failed to resolve session cookie', error);
  }

  if (hasStaticCredential(request)) {
    return NextResponse.next();
  }

  if (isApiRoute(request.nextUrl.pathname) || request.method !== 'GET') {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }

  return buildLoginRedirect(request);
}

export const config = {
  matcher: ['/((?!_next|favicon.ico|api/auth|api/health).*)']
};
