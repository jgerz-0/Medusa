import { NextRequest, NextResponse } from 'next/server';
import { persistAuthorizationState, startLogin } from '@/lib/auth';

function sanitizeReturnTo(value: string | null, origin: string): string | undefined {
  if (!value) {
    return undefined;
  }
  if (value.startsWith('/')) {
    return value;
  }
  try {
    const parsed = new URL(value, origin);
    if (parsed.origin === origin) {
      return `${parsed.pathname}${parsed.search}${parsed.hash}`;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

export async function GET(request: NextRequest) {
  const origin = request.nextUrl.origin;
  const returnTo = sanitizeReturnTo(
    request.nextUrl.searchParams.get('returnTo') ?? request.nextUrl.searchParams.get('callbackUrl'),
    origin
  );

  try {
    const { authorizationUrl, state } = await startLogin(returnTo, origin);
    const response = NextResponse.redirect(authorizationUrl);
    await persistAuthorizationState(response, state);
    response.headers.set('Cache-Control', 'no-store');
    return response;
  } catch (error) {
    console.error('Failed to initiate OIDC login', error);
    return NextResponse.json({ error: 'oidc_login_init_failed' }, { status: 500 });
  }
}
