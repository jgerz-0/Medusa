import { controllerApiKey, controllerBaseUrl, controllerJwt } from './config';
import type { Finding, Scan, Target } from './types';

type ApiCollectionResponse<T> = {
  data: T;
};

type ApiItemResponse<T> = {
  data: T;
};

export interface ValidationIssue {
  field: string;
  message: string;
}

export class ControllerError extends Error {
  status: number;
  details?: unknown;

  constructor(message: string, status: number, details?: unknown) {
    super(message);
    this.name = 'ControllerError';
    this.status = status;
    this.details = details;
  }
}

export class ControllerValidationError extends ControllerError {
  issues: ValidationIssue[];

  constructor(message: string, status: number, issues: ValidationIssue[], details?: unknown) {
    super(message, status, details);
    this.name = 'ControllerValidationError';
    this.issues = issues;
  }
}

function buildAuthHeaders(): HeadersInit {
  const headers: Record<string, string> = {
    Accept: 'application/json'
  };

  if (controllerApiKey) {
    headers['X-API-Key'] = controllerApiKey;
    // Mirror the controller's API key contract over Authorization to keep proxies simple.
    headers['Authorization'] = `Bearer ${controllerApiKey}`;
  }

  if (controllerJwt) {
    headers['Authorization'] = `Bearer ${controllerJwt}`;
  }

  return headers;
}

function normalizeHeaders(headers?: HeadersInit): Headers {
  const resolved = new Headers(headers);
  return resolved;
}

function parseIssues(detail: unknown): ValidationIssue[] {
  if (!Array.isArray(detail)) {
    return [];
  }

  return detail
    .map((item) => {
      if (!item || typeof item !== 'object') {
        return null;
      }

      const issue = item as { loc?: unknown; msg?: unknown };
      const message = typeof issue.msg === 'string' ? issue.msg : 'Invalid value';
      let field = 'unknown';

      if (Array.isArray(issue.loc)) {
        const path = issue.loc
          .filter((segment) => typeof segment === 'string' && segment !== 'body')
          .join('.');
        if (path) {
          field = path;
        }
      }

      return { field, message } satisfies ValidationIssue;
    })
    .filter((value): value is ValidationIssue => value !== null);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const url = `${controllerBaseUrl.replace(/\/$/, '')}${path}`;
  const baseHeaders = normalizeHeaders(buildAuthHeaders());
  if (init.headers) {
    const extraHeaders = normalizeHeaders(init.headers);
    extraHeaders.forEach((value, key) => {
      baseHeaders.set(key, value);
    });
  }

  const response = await fetch(url, {
    cache: 'no-store',
    ...init,
    headers: baseHeaders
  });

  if (!response.ok) {
    const contentType = response.headers.get('content-type') ?? '';
    let details: unknown = undefined;
    let message = `Controller request to ${url} failed with ${response.status}.`;

    if (contentType.includes('application/json')) {
      try {
        details = await response.json();
      } catch {
        details = await response.text();
      }
    } else {
      details = await response.text();
    }

    if (details && typeof details === 'object' && 'detail' in (details as Record<string, unknown>)) {
      const detail = (details as Record<string, unknown>).detail;
      if (typeof detail === 'string') {
        message = detail;
      }

      const issues = parseIssues(detail);
      if (issues.length > 0) {
        if (message === `Controller request to ${url} failed with ${response.status}.`) {
          message = 'Controller rejected the payload. Review validation errors.';
        }
        throw new ControllerValidationError(message, response.status, issues, details);
      }
    } else if (typeof details === 'string' && details.trim().length > 0) {
      message = details;
    }

    throw new ControllerError(message, response.status, details);
  }

  return (await response.json()) as T;
}

export async function fetchScans(): Promise<Scan[]> {
  const payload = await request<ApiCollectionResponse<Scan[]>>('/scans');
  return payload.data;
}

export async function fetchFindings(): Promise<Finding[]> {
  const payload = await request<ApiCollectionResponse<Finding[]>>('/findings');
  return payload.data;
}

export async function fetchFinding(id: string): Promise<Finding> {
  const payload = await request<ApiItemResponse<Finding>>(`/findings/${id}`);
  return payload.data;
}

export async function fetchTargets(): Promise<Target[]> {
  const payload = await request<ApiCollectionResponse<Target[]>>('/targets');
  return payload.data;
}

export interface CreateScanPayload {
  target_id: string;
  profile: string;
  requested_hosts?: string[];
}

export async function createScan(payload: CreateScanPayload): Promise<Scan> {
  const response = await request<ApiItemResponse<Scan>>('/scans', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  return response.data;
}
