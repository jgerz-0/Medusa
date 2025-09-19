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
