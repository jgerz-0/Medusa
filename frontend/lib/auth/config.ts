function readEnv(name: string): string | undefined {
  const value = process.env[name];
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function required(name: string): string {
  const value = readEnv(name);
  if (!value) {
    throw new Error(`${name} must be configured to enable OIDC authentication.`);
  }
  return value;
}

export function getOidcIssuer(): string {
  return required('MEDUSA_OIDC_ISSUER');
}

export function getOidcClientId(): string {
  return required('MEDUSA_OIDC_CLIENT_ID');
}

export function getOidcClientSecret(): string {
  return required('MEDUSA_OIDC_CLIENT_SECRET');
}

export function getOidcAudience(): string | undefined {
  return readEnv('MEDUSA_OIDC_AUDIENCE');
}

export function getOidcScopes(): string {
  return readEnv('MEDUSA_OIDC_SCOPES') ?? 'openid profile email offline_access';
}

export function getSessionSecret(): string {
  return required('MEDUSA_SESSION_SECRET');
}

export function getOidcAuthorizationEndpointOverride(): string | undefined {
  return readEnv('MEDUSA_OIDC_AUTHORIZATION_ENDPOINT');
}

export function getOidcTokenEndpointOverride(): string | undefined {
  return readEnv('MEDUSA_OIDC_TOKEN_ENDPOINT');
}

export function getOidcUserinfoEndpointOverride(): string | undefined {
  return readEnv('MEDUSA_OIDC_USERINFO_ENDPOINT');
}

export function getSessionTtlSeconds(): number {
  const raw = readEnv('MEDUSA_SESSION_TTL_SECONDS');
  if (!raw) {
    return 7 * 24 * 60 * 60; // default to seven days
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 300) {
    throw new Error('MEDUSA_SESSION_TTL_SECONDS must be an integer >= 300.');
  }
  return parsed;
}

export function getOidcTokenSkewSeconds(): number {
  const raw = readEnv('MEDUSA_OIDC_TOKEN_SKEW_SECONDS');
  if (!raw) {
    return 60;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new Error('MEDUSA_OIDC_TOKEN_SKEW_SECONDS must be a non-negative integer.');
  }
  return parsed;
}

export function getOidcRequestTimeoutSeconds(): number {
  const raw = readEnv('MEDUSA_OIDC_REQUEST_TIMEOUT_SECONDS');
  if (!raw) {
    return 10;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    throw new Error('MEDUSA_OIDC_REQUEST_TIMEOUT_SECONDS must be an integer >= 1.');
  }
  return parsed;
}
