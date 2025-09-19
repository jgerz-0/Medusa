# Medusa Operations Console (Frontend)

This Next.js dashboard surfaces controller scans and findings for security analysts. It is hardened with API key-aware
authentication middleware to reflect the controller's RBAC model.

## Getting started

```bash
cd frontend
pnpm install
pnpm dev
```

Configure credentials in `.env.local` (copy from `.env.example`). Requests to the controller include the API key and optional
JWT automatically. The default middleware credentials are `analyst` / `analyst`; override `DASHBOARD_BASIC_USER` and `DASHBOARD_BASIC_PASSWORD`
for your environment.
Copy `frontend/.env.example` to `.env.local` and tailor the values for your deployment. Requests to the controller include the
API key and optional JWT automatically. `CONTROLLER_API_KEY` and `CONTROLLER_JWT` must match the credentials issued by the
controller for this dashboard. The default middleware credentials are `analyst` / `analyst`; override `DASHBOARD_BASIC_USER` and
`DASHBOARD_BASIC_PASSWORD` for your environment.

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

- `middleware.ts` enforces either HTTP Basic or Bearer token auth using the configured API key/JWT.
- Shared components (`LayoutShell`, `DataTable`, `StatusBadge`) keep table rendering consistent across pages.
- Tailwind theme defaults are documented in [`THEME.md`](./THEME.md) for future iteration by the design system team.
