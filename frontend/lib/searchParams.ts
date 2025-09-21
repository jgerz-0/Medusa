// Helper utilities to safely merge existing URL search parameters with deterministic pagination links.
type SearchParamValue = string | string[] | undefined;

export type SearchParamsInput = Record<string, SearchParamValue> | undefined;

interface BuildHrefOptions {
  basePath: string;
  params?: SearchParamsInput;
  updates: Record<string, string | string[] | null | undefined>;
}

function appendParam(target: URLSearchParams, key: string, value: string) {
  const normalized = value.trim();
  if (!normalized) {
    return;
  }
  target.append(key, normalized);
}

function seedParams(source: SearchParamsInput): URLSearchParams {
  const result = new URLSearchParams();

  if (!source) {
    return result;
  }

  for (const [key, raw] of Object.entries(source)) {
    if (Array.isArray(raw)) {
      for (const candidate of raw) {
        if (typeof candidate === 'string') {
          appendParam(result, key, candidate);
        }
      }
      continue;
    }

    if (typeof raw === 'string') {
      appendParam(result, key, raw);
    }
  }

  return result;
}

export function buildSearchParamsHref({ basePath, params, updates }: BuildHrefOptions): string {
  const search = seedParams(params);

  for (const [key, value] of Object.entries(updates)) {
    search.delete(key);

    if (value === null || value === undefined) {
      continue;
    }

    if (Array.isArray(value)) {
      for (const entry of value) {
        appendParam(search, key, `${entry}`);
      }
      continue;
    }

    appendParam(search, key, `${value}`);
  }

  const query = search.toString();
  return query ? `${basePath}?${query}` : basePath;
}
