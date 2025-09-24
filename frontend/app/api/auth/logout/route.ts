import { NextRequest, NextResponse } from 'next/server';
import { clearAuthorizationState, clearSession } from '@/lib/auth';

function sanitizeReturnTo(value: string | null, origin: string): URL {
  if (value && value.startsWith('/')) {
    return new URL(value, origin);
  }
  return new URL('/', origin);
}

function handle(request: NextRequest): NextResponse {
  const origin = request.nextUrl.origin;
  const destination = sanitizeReturnTo(request.nextUrl.searchParams.get('returnTo'), origin);
  const response = NextResponse.redirect(destination);
  clearSession(response);
  clearAuthorizationState(response);
  response.headers.set('Cache-Control', 'no-store');
  return response;
}

export function GET(request: NextRequest) {
  return handle(request);
}

export function POST(request: NextRequest) {
  return handle(request);
}
