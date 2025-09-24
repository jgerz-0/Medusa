import type { NextResponse } from 'next/server';
import {
  getOidcIssuer,
  getOidcTokenSkewSeconds,
  getSessionSecret,
  getSessionTtlSeconds
} from './config';
import { encrypt, decrypt } from './session';
import {
  buildAuthorizationUrl,
  decodeIdTokenClaims,
  exchangeAuthorizationCode,
  fetchUserInfo,
  refreshTokens,
  type OidcSessionClaims,
  type TokenResponse
} from './oidc';
import { toBase64Url } from './encoding';

export interface AuthorizationState {
  state: string;
  codeVerifier: string;
  returnTo?: string;
  issuedAt: number;
}

export interface MedusaSession {
  subject: string;
  issuer: string;
  name?: string;
  email?: string;
  roles?: string[];
  groups?: string[];
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  scope?: string;
  tokenType: string;
  accessTokenExpiresAt: number;
  issuedAt: number;
}

const SESSION_COOKIE_NAME = process.env.NODE_ENV === 'production' ? '__Secure-medusa.session' : 'medusa.session';
const STATE_COOKIE_NAME = process.env.NODE_ENV === 'production' ? '__Host-medusa.state' : 'medusa.state';
const STATE_MAX_AGE = 5 * 60; // five minutes

function secureCookie(): boolean {
  return process.env.NODE_ENV === 'production';
}

export function getSessionCookieName(): string {
  return SESSION_COOKIE_NAME;
}

export function getStateCookieName(): string {
  return STATE_COOKIE_NAME;
}

function sanitizeString(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function sanitizeStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }
  const normalized = value
    .map((entry) => (typeof entry === 'string' ? entry.trim() : undefined))
    .filter((entry): entry is string => !!entry && entry.length > 0);
  return normalized.length > 0 ? normalized : undefined;
}

function now(): number {
  return Date.now();
}

export function createRandomString(byteLength = 32): string {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi) {
    throw new Error('Web Crypto API is unavailable.');
  }
  const buffer = cryptoApi.getRandomValues(new Uint8Array(byteLength));
  return toBase64Url(buffer);
}

export async function deriveCodeChallenge(codeVerifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const digest = await globalThis.crypto.subtle.digest('SHA-256', encoder.encode(codeVerifier));
  return toBase64Url(new Uint8Array(digest));
}

export async function persistAuthorizationState(
  response: NextResponse,
  state: AuthorizationState
): Promise<void> {
  const secret = getSessionSecret();
  const value = await encrypt(state, secret);
  response.cookies.set({
    name: STATE_COOKIE_NAME,
    value,
    httpOnly: true,
    sameSite: 'lax',
    secure: secureCookie(),
    path: '/',
    maxAge: STATE_MAX_AGE,
    priority: 'high'
  });
}

export async function readAuthorizationState(
  cookieStore: { get: (name: string) => { value: string } | undefined }
): Promise<AuthorizationState | null> {
  const secret = getSessionSecret();
  const cookie = cookieStore.get(STATE_COOKIE_NAME);
  if (!cookie?.value) {
    return null;
  }
  return decrypt<AuthorizationState>(cookie.value, secret);
}

export function clearAuthorizationState(response: NextResponse): void {
  response.cookies.set({
    name: STATE_COOKIE_NAME,
    value: '',
    httpOnly: true,
    sameSite: 'lax',
    secure: secureCookie(),
    path: '/',
    maxAge: 0,
    priority: 'high'
  });
}

export async function persistSession(
  response: NextResponse,
  session: MedusaSession
): Promise<void> {
  const secret = getSessionSecret();
  const value = await encrypt(session, secret);
  response.cookies.set({
    name: SESSION_COOKIE_NAME,
    value,
    httpOnly: true,
    sameSite: 'lax',
    secure: secureCookie(),
    path: '/',
    maxAge: getSessionTtlSeconds(),
    priority: 'high'
  });
}

export function clearSession(response: NextResponse): void {
  response.cookies.set({
    name: SESSION_COOKIE_NAME,
    value: '',
    httpOnly: true,
    sameSite: 'lax',
    secure: secureCookie(),
    path: '/',
    maxAge: 0,
    priority: 'high'
  });
}

export async function readSession(
  cookieStore: { get: (name: string) => { value: string } | undefined }
): Promise<MedusaSession | null> {
  const secret = getSessionSecret();
  const cookie = cookieStore.get(SESSION_COOKIE_NAME);
  if (!cookie?.value) {
    return null;
  }
  return decrypt<MedusaSession>(cookie.value, secret);
}

export function isAccessTokenExpired(session: MedusaSession): boolean {
  const skewMs = getOidcTokenSkewSeconds() * 1000;
  return session.accessTokenExpiresAt - skewMs <= now();
}

function mergeClaims(
  tokenClaims: OidcSessionClaims | null,
  userInfo: OidcSessionClaims | null
): OidcSessionClaims | null {
  if (!tokenClaims && !userInfo) {
    return null;
  }
  return {
    ...(userInfo ?? {}),
    ...(tokenClaims ?? {})
  } as OidcSessionClaims;
}

async function buildSessionFromTokenResponse(
  token: TokenResponse,
  previous?: MedusaSession
): Promise<MedusaSession> {
  if (!token.access_token) {
    throw new Error('OIDC response did not include an access token.');
  }

  const tokenClaims = token.id_token ? decodeIdTokenClaims(token.id_token) : null;
  const userInfo = await fetchUserInfo(token.access_token);
  const combined = mergeClaims(tokenClaims, userInfo);

  const subject = sanitizeString(combined?.sub) ?? previous?.subject;
  if (!subject) {
    throw new Error('OIDC claims did not include a subject identifier.');
  }

  const name =
    sanitizeString(combined?.name) ??
    sanitizeString(combined?.preferred_username) ??
    previous?.name;
  const email = sanitizeString(combined?.email) ?? previous?.email;
  const roles = sanitizeStringArray(combined?.roles) ?? previous?.roles;
  const groups = sanitizeStringArray(combined?.groups) ?? previous?.groups;
  const expiresInSeconds =
    typeof token.expires_in === 'number' && Number.isFinite(token.expires_in) && token.expires_in > 0
      ? token.expires_in
      : 3600;

  const issuedAt = now();

  return {
    subject,
    issuer: previous?.issuer ?? getOidcIssuer(),
    name,
    email,
    roles,
    groups,
    accessToken: token.access_token,
    refreshToken: token.refresh_token ?? previous?.refreshToken,
    idToken: token.id_token ?? previous?.idToken,
    scope: token.scope ?? previous?.scope,
    tokenType: sanitizeString(token.token_type) ?? previous?.tokenType ?? 'Bearer',
    accessTokenExpiresAt: issuedAt + expiresInSeconds * 1000,
    issuedAt
  } satisfies MedusaSession;
}

export async function createSessionFromAuthorizationCode(
  code: string,
  codeVerifier: string,
  redirectUri: string
): Promise<MedusaSession> {
  const token = await exchangeAuthorizationCode(code, codeVerifier, redirectUri);
  return buildSessionFromTokenResponse(token);
}

export async function refreshSession(session: MedusaSession): Promise<MedusaSession | null> {
  if (!session.refreshToken) {
    return null;
  }

  try {
    const token = await refreshTokens(session.refreshToken);
    return await buildSessionFromTokenResponse(token, session);
  } catch (error) {
    console.error('OIDC token refresh failed', error);
    return null;
  }
}

export async function startLogin(returnTo: string | undefined, origin: string): Promise<{
  authorizationUrl: URL;
  state: AuthorizationState;
}> {
  const codeVerifier = createRandomString(64);
  const state = createRandomString(32);
  const codeChallenge = await deriveCodeChallenge(codeVerifier);
  const redirectUri = new URL('/api/auth/callback', origin).toString();
  const authorizationUrl = await buildAuthorizationUrl({
    state,
    codeChallenge,
    redirectUri,
    returnTo
  });
  return {
    authorizationUrl,
    state: {
      state,
      codeVerifier,
      returnTo,
      issuedAt: now()
    }
  };
}

export { validateBearerToken, clearCachedVerificationKeys } from './validator';
