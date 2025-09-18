import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import {
  controllerApiKey,
  controllerJwt,
  dashboardPassword,
  dashboardUser
} from '@/lib/config';

function unauthorized(): NextResponse {
  return new NextResponse('Unauthorized', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="Medusa Operations", charset="UTF-8"'
    }
  });
}

function validateBasic(authHeader: string): boolean {
  const encoded = authHeader.replace(/^Basic\s+/i, '');
  try {
    const decoded = atob(encoded);
    const [user, password] = decoded.split(':');
    return user === dashboardUser && password === dashboardPassword;
  } catch (error) {
    console.error('Failed to decode basic auth payload', error);
    return false;
  }
}

function validateBearer(authHeader: string): boolean {
  const token = authHeader.replace(/^Bearer\s+/i, '');
  return (
    !!token &&
    (token === dashboardPassword || token === controllerApiKey || token === controllerJwt)
  );
}

export function middleware(request: NextRequest) {
  // Enforce auth only when a credential is configured.
  if (!dashboardPassword && !controllerApiKey && !controllerJwt) {
    return NextResponse.next();
  }

  const header = request.headers.get('authorization');

  if (!header) {
    return unauthorized();
  }

  if (header.toLowerCase().startsWith('basic')) {
    return validateBasic(header) ? NextResponse.next() : unauthorized();
  }

  if (header.toLowerCase().startsWith('bearer')) {
    return validateBearer(header) ? NextResponse.next() : unauthorized();
  }

  return unauthorized();
}

export const config = {
  matcher: ['/((?!_next|favicon.ico|api/health).*)']
};
