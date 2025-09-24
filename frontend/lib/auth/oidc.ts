import {
  getOidcAudience,
  getOidcAuthorizationEndpointOverride,
  getOidcClientId,
  getOidcClientSecret,
  getOidcIssuer,
  getOidcRequestTimeoutSeconds,
  getOidcScopes,
  getOidcTokenEndpointOverride,
  getOidcUserinfoEndpointOverride
} from './config';
import { decodeJson } from './encoding';

export interface OidcConfiguration {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userinfoEndpoint?: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  id_token?: string;
  token_type?: string;
  scope?: string;
}

export interface OidcSessionClaims {
  sub: string;
  name?: string;
  email?: string;
  preferred_username?: string;
  roles?: string[];
  groups?: string[];
  [key: string]: unknown;
}

let cachedConfiguration: Promise<OidcConfiguration> | null = null;

function timeoutController(): AbortController {
  const timeoutMs = getOidcRequestTimeoutSeconds() * 1000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  controller.signal.addEventListener('abort', () => clearTimeout(timer));
  return controller;
}

async function fetchConfiguration(): Promise<OidcConfiguration> {
  const issuer = getOidcIssuer().replace(/\/$/, '');
  const wellKnownUrl = `${issuer}/.well-known/openid-configuration`;
  const controller = timeoutController();
  try {
    const response = await fetch(wellKnownUrl, { signal: controller.signal });
    if (!response.ok) {
      throw new Error(`OIDC discovery request failed with status ${response.status}.`);
    }
    const payload = (await response.json()) as Record<string, unknown>;
    const authorizationEndpoint =
      getOidcAuthorizationEndpointOverride() ??
      (typeof payload.authorization_endpoint === 'string' ? payload.authorization_endpoint : undefined);
    const tokenEndpoint =
      getOidcTokenEndpointOverride() ??
      (typeof payload.token_endpoint === 'string' ? payload.token_endpoint : undefined);
    const userinfoEndpoint =
      getOidcUserinfoEndpointOverride() ??
      (typeof payload.userinfo_endpoint === 'string' ? payload.userinfo_endpoint : undefined);

    if (!authorizationEndpoint || !tokenEndpoint) {
      throw new Error('OIDC discovery document did not include authorization or token endpoints.');
    }

    return {
      issuer: typeof payload.issuer === 'string' ? payload.issuer : issuer,
      authorizationEndpoint,
      tokenEndpoint,
      userinfoEndpoint
    } satisfies OidcConfiguration;
  } finally {
    controller.abort();
  }
}

export async function getOidcConfiguration(): Promise<OidcConfiguration> {
  if (!cachedConfiguration) {
    cachedConfiguration = fetchConfiguration();
  }
  return cachedConfiguration;
}

interface AuthorizationUrlOptions {
  state: string;
  codeChallenge: string;
  redirectUri: string;
  returnTo?: string;
}

export async function buildAuthorizationUrl(options: AuthorizationUrlOptions): Promise<URL> {
  const { authorizationEndpoint } = await getOidcConfiguration();
  const scopes = getOidcScopes();
  const audience = getOidcAudience();
  const url = new URL(authorizationEndpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', getOidcClientId());
  url.searchParams.set('redirect_uri', options.redirectUri);
  url.searchParams.set('scope', scopes);
  url.searchParams.set('state', options.state);
  url.searchParams.set('code_challenge', options.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  if (audience) {
    url.searchParams.set('audience', audience);
  }
  if (options.returnTo) {
    url.searchParams.set('prompt', 'consent');
  }
  return url;
}

async function postForm(url: string, body: URLSearchParams): Promise<Response> {
  const controller = timeoutController();
  try {
    return await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: controller.signal
    });
  } finally {
    controller.abort();
  }
}

export async function exchangeAuthorizationCode(
  code: string,
  codeVerifier: string,
  redirectUri: string
): Promise<TokenResponse> {
  const { tokenEndpoint } = await getOidcConfiguration();
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    client_id: getOidcClientId(),
    code_verifier: codeVerifier
  });
  const clientSecret = getOidcClientSecret();
  if (clientSecret) {
    params.set('client_secret', clientSecret);
  }

  const response = await postForm(tokenEndpoint, params);
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`OIDC token exchange failed: ${detail || response.status}`);
  }
  return (await response.json()) as TokenResponse;
}

export async function refreshTokens(refreshToken: string): Promise<TokenResponse> {
  const { tokenEndpoint } = await getOidcConfiguration();
  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: getOidcClientId()
  });
  const clientSecret = getOidcClientSecret();
  if (clientSecret) {
    params.set('client_secret', clientSecret);
  }

  const response = await postForm(tokenEndpoint, params);
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`OIDC token refresh failed: ${detail || response.status}`);
  }
  return (await response.json()) as TokenResponse;
}

export async function fetchUserInfo(accessToken: string): Promise<OidcSessionClaims | null> {
  const { userinfoEndpoint } = await getOidcConfiguration();
  if (!userinfoEndpoint) {
    return null;
  }

  const controller = timeoutController();
  try {
    const response = await fetch(userinfoEndpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: controller.signal
    });
    if (!response.ok) {
      return null;
    }
    return (await response.json()) as OidcSessionClaims;
  } catch {
    return null;
  } finally {
    controller.abort();
  }
}

export function decodeIdTokenClaims(idToken: string): OidcSessionClaims | null {
  const segments = idToken.split('.');
  if (segments.length < 2) {
    return null;
  }
  try {
    return decodeJson<OidcSessionClaims>(segments[1]);
  } catch (error) {
    console.error('Failed to decode ID token claims', error);
    return null;
  }
}
