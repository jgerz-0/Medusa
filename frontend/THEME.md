# Theme Defaults

The operations console uses a dark, high-contrast palette that aligns with security operation center environments. The palette
is intentionally minimal to keep focus on severity signals.

## Palette

| Token | Value | Notes |
| --- | --- | --- |
| `brand.DEFAULT` | `#111827` | Primary chrome background (nav, cards). |
| `brand.foreground` | `#F9FAFB` | Default text color for high-emphasis copy. |
| `brand.muted` | `#1F2937` | Subdued panels and hover states. |
| `surface.DEFAULT` | `#0F172A` | Page background. |
| `surface.subtle` | `#111827` | Body background used in `globals.css`. |
| `surface.muted` | `#1E293B` | Card outlines and table dividers. |

## Status + Severity Colors

| Token | Hex | Usage |
| --- | --- | --- |
| `status.queued` | `#6366F1` | Pending scan execution. |
| `status.running` | `#0EA5E9` | Actively executing scan. |
| `status.completed` | `#10B981` | Successful completion. |
| `status.failed` | `#EF4444` | Terminal failure / triage required. |
| `status.open` | `#F97316` | Open finding awaiting validation. |
| `status.acknowledged` | `#EAB308` | Finding acknowledged by analyst. |
| `status.resolved` | `#22C55E` | Remediated finding pending verification. |
| `severity.critical` | `#7F1D1D` | Priority 0 incidents. |
| `severity.high` | `#B91C1C` | Priority 1 incidents. |
| `severity.medium` | `#D97706` | Priority 2 findings. |
| `severity.low` | `#2563EB` | Informational but notable. |
| `severity.info` | `#6B7280` | Noise/observational data. |

## Typography

- Primary font: `IBM Plex Sans` (system fallback) for clarity.
- Monospace font: `IBM Plex Mono` for identifiers, timestamps, and API payloads.

## Components

- **LayoutShell** – Provides the navigation chrome and ensures pages inherit the SOC aesthetic.
- **DataTable** – Shared table layout with consistent padding, typography, and hover treatment.
- **StatusBadge** – Uses severity/status tokens above to present state transitions consistently.

Future design work should extend these tokens rather than overriding inline styles to keep the UI auditable and consistent.
