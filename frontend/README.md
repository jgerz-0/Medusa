# Medusa Operations Console (Frontend)

This Next.js dashboard surfaces controller scans and findings for security analysts. It is hardened with API key-aware
authentication middleware to reflect the controller's RBAC model.

## Getting started

```bash
cd frontend
pnpm install
pnpm dev
```

Copy `frontend/.env.example` to `.env.local` and tailor the values for your deployment. Populate the following values so the
dashboard can complete the PKCE OIDC handshake against your identity provider:

- `MEDUSA_SESSION_SECRET` – random 32+ byte string used to encrypt the session cookie.
- `MEDUSA_OIDC_ISSUER` – issuer URL published by the IdP.
- `MEDUSA_OIDC_CLIENT_ID` / `MEDUSA_OIDC_CLIENT_SECRET` – OAuth2 client credentials provisioned for the dashboard.
- `MEDUSA_OIDC_AUDIENCE` – audience expected by the Medusa controller (often the controller's client ID).
- `CONTROLLER_API_BASE_URL` – controller URL (defaults to `http://127.0.0.1:8000`).
- `CONTROLLER_API_KEY` / `CONTROLLER_JWT` – optional automation credentials used when no interactive session exists.

The middleware redirects unauthenticated analysts to `/api/auth/login`, exchanges the authorization code for tokens, and stores
the resulting access/refresh pair inside an AES-GCM encrypted `__Secure-medusa.session` cookie. API helpers automatically attach
the decrypted bearer token to controller requests.

## Orchestrating scans

1. Navigate to `/scans` and pick an authorized target. ZAP and SQLMap scanners require HTTP or HTTPS scope; nuclei supports any
   registered host.
2. Choose a scanner:
   - **Nuclei** – select one of the hardened profiles. Optional host overrides are pre-wired per preset.
   - **OWASP ZAP** – pick the policy and mode (baseline/full) and optionally tune the rate limit. Invalid values are coerced to
     the controller defaults before dispatch.
   - **SQLMap** – lock level (1–5), risk (0–3), and optional request delay to keep noisy payloads in check.
3. Submit the form. The UI mirrors controller validation, surfaces inline errors (policy/mode/risk/target scope), and forwards
   scanner-specific parameters along with the selected target scope. The scans table now includes the scanner column so you can
   confirm which worker executed each job.

## Testing

```bash
pnpm test
```

Component tests rely on deterministic fixtures to ensure rendering remains stable as the UI evolves.

## Linting

```bash
pnpm lint
```

## Deployment notes

- `middleware.ts` validates the encrypted session cookie, transparently refreshes OIDC tokens, and falls back to `CONTROLLER_API_KEY`/`CONTROLLER_JWT` headers for automation.
- Shared components (`LayoutShell`, `DataTable`, `StatusBadge`) keep table rendering consistent across pages.
- Tailwind theme defaults are documented in [`THEME.md`](./THEME.md) for future iteration by the design system team.
