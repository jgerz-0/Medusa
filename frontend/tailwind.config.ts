import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './app/**/*.{ts,tsx}',
    './components/**/*.{ts,tsx}',
    './lib/**/*.{ts,tsx}'
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          DEFAULT: '#111827',
          foreground: '#F9FAFB',
          muted: '#1F2937'
        },
        surface: {
          DEFAULT: '#0F172A',
          subtle: '#111827',
          muted: '#1E293B'
        },
        status: {
          queued: '#6366F1',
          running: '#0EA5E9',
          completed: '#10B981',
          failed: '#EF4444',
          open: '#F97316',
          'pending-validation': '#38BDF8',
          acknowledged: '#EAB308',
          invalidated: '#94A3B8',
          resolved: '#22C55E'
        },
        severity: {
          critical: '#7F1D1D',
          high: '#B91C1C',
          medium: '#D97706',
          low: '#2563EB',
          info: '#6B7280'
        }
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'SFMono-Regular']
      },
      boxShadow: {
        card: '0 12px 30px -12px rgba(15, 23, 42, 0.45)'
      }
    }
  },
  plugins: []
};

export default config;
