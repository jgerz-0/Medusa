import { NextRequest, NextResponse } from 'next/server';
import {
  clearAuthorizationState,
  clearSession,
  createSessionFromAuthorizationCode,
  persistSession,
  readAuthorizationState
} from '@/lib/auth';

function buildRedirect(origin: string, returnTo?: string): URL {
  if (returnTo && returnTo.startsWith('/')) {
    return new URL(returnTo, origin);
  }
  return new URL('/', origin);
}

function jsonError(message: string, status: number): NextResponse {
  return NextResponse.json({ error: message }, { status, headers: { 'Cache-Control': 'no-store' } });
}

export async function GET(request: NextRequest) {
  const code = request.nextUrl.searchParams.get('code');
  const stateParam = request.nextUrl.searchParams.get('state');

  if (!code || !stateParam) {
    return jsonError('missing_callback_parameters', 400);
  }

  const storedState = await readAuthorizationState(request.cookies);
  if (!storedState || storedState.state !== stateParam) {
    return jsonError('state_verification_failed', 400);
  }

  try {
    const redirectUri = new URL('/api/auth/callback', request.nextUrl.origin).toString();
    const session = await createSessionFromAuthorizationCode(code, storedState.codeVerifier, redirectUri);
    const destination = buildRedirect(request.nextUrl.origin, storedState.returnTo);
    const response = NextResponse.redirect(destination);
    await persistSession(response, session);
    clearAuthorizationState(response);
    response.headers.set('Cache-Control', 'no-store');
    return response;
  } catch (error) {
    console.error('OIDC callback processing failed', error);
    const response = jsonError('oidc_callback_failed', 502);
    clearAuthorizationState(response);
    clearSession(response);
    return response;
  }
}
