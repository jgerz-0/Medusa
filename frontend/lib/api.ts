import { controllerApiKey, controllerBaseUrl, controllerJwt } from './config';
import type {
  Finding,
  FindingComment,
  FindingTimelineEvent,
  FindingsTimelineBucket,
  ReportExportResponse,
  Scan,
  Target,
  FindingTicket
} from './types';

type ApiCollectionResponse<T> = {
  data: T;
};

type ApiItemResponse<T> = {
  data: T;
};

interface FindingItemResponse extends ApiItemResponse<Finding> {}

export interface FindingsQuery {
  targetId?: string;
  scanId?: string;
  severity?: string;
  status?: string;
  tag?: string;
  assignedTo?: string;
  from?: string;
  to?: string;
  scope?: string;
}

function buildPath(
  path: string,
  params?: Record<string, string | string[] | undefined>
): string {
  if (!params) {
    return path;
  }

  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item !== undefined && item !== null && `${item}`.trim() !== '') {
          search.append(key, `${item}`.trim());
        }
      }
      continue;
    }

    if (value === undefined || value === null) {
      continue;
    }

    const normalized = `${value}`.trim();
    if (normalized === '') {
      continue;
    }
    search.set(key, normalized);
  }

  const query = search.toString();
  return query ? `${path}?${query}` : path;
}

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

const validationFieldAliases: Record<string, string> = {
  target_id: 'targetId',
  'parameters.profile': 'profile',
  'parameters.requested_hosts': 'requestedHosts',
  'parameters.policy': 'policy',
  'parameters.mode': 'mode',
  'parameters.rate_limit': 'rateLimit',
  'parameters.ajax_spider': 'ajaxSpider',
  'parameters.level': 'level',
  'parameters.risk': 'risk',
  'parameters.request_delay': 'requestDelay'
};

function normalizeValidationField(field: string): string {
  if (!field) {
    return field;
  }

  for (const [rawField, normalizedField] of Object.entries(validationFieldAliases)) {
    if (field === rawField) {
      return normalizedField;
    }

    if (field.startsWith(`${rawField}.`)) {
      return `${normalizedField}${field.slice(rawField.length)}`;
    }
  }

  const segments = field.split('.');
  const normalizedSegments = segments.map((segment) => {
    if (!segment.includes('_')) {
      return segment;
    }

    return segment.replace(/_([a-z])/g, (_, character: string) => character.toUpperCase());
  });

  return normalizedSegments.join('.');
}

export class ControllerValidationError extends ControllerError {
  issues: ValidationIssue[];

  constructor(message: string, status: number, issues: ValidationIssue[], details?: unknown) {
    super(message, status, details);
    this.name = 'ControllerValidationError';
    this.issues = issues.map((issue) => ({
      ...issue,
      field: normalizeValidationField(issue.field)
    }));
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
          field = normalizeValidationField(path);
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

export async function fetchFindings(query?: FindingsQuery): Promise<Finding[]> {
  const path = buildPath('/findings', {
    target_id: query?.targetId,
    scan_id: query?.scanId,
    severity: query?.severity,
    status: query?.status,
    tag: query?.tag,
    assigned_to: query?.assignedTo,
    from: query?.from,
    to: query?.to,
    scope: query?.scope
  });
  const payload = await request<ApiCollectionResponse<Finding[]>>(path);
  return payload.data;
}

export async function fetchFinding(id: string): Promise<Finding> {
  const payload = await request<ApiItemResponse<Finding>>(`/findings/${id}`);
  return payload.data;
}

export async function fetchFindingComments(findingId: string): Promise<FindingComment[]> {
  const payload = await request<ApiCollectionResponse<FindingComment[]>>(
    `/findings/${findingId}/comments`
  );
  return payload.data;
}

export async function fetchFindingTimeline(
  findingId: string
): Promise<FindingTimelineEvent[]> {
  const payload = await request<ApiCollectionResponse<FindingTimelineEvent[]>>(
    `/findings/${findingId}/timeline`
  );
  return payload.data;
}

export async function fetchFindingsTimeline(
  query?: FindingsQuery
): Promise<FindingsTimelineBucket[]> {
  const path = buildPath('/findings/timeline', {
    target_id: query?.targetId,
    scan_id: query?.scanId,
    severity: query?.severity,
    status: query?.status,
    tag: query?.tag,
    assigned_to: query?.assignedTo,
    from: query?.from,
    to: query?.to
  });
  const payload = await request<ApiCollectionResponse<FindingsTimelineBucket[]>>(path);
  return payload.data;
}

export async function createFindingComment(
  findingId: string,
  message: string
): Promise<FindingComment> {
  return request<FindingComment>(`/findings/${findingId}/comments`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message })
  });
}

export async function assignFinding(
  findingId: string,
  assignee: string
): Promise<Finding> {
  const payload = await request<FindingItemResponse>(`/findings/${findingId}/assign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ assignee })
  });
  return payload.data;
}

export async function updateFindingStatus(
  findingId: string,
  statusValue: Finding['status']
): Promise<Finding> {
  const payload = await request<FindingItemResponse>(`/findings/${findingId}/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: statusValue })
  });
  return payload.data;
}

export async function updateFindingTags(
  findingId: string,
  tags: string[]
): Promise<Finding> {
  const payload = await request<FindingItemResponse>(`/findings/${findingId}/tags`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tags })
  });
  return payload.data;
}

export interface FindingsReportRequest {
  findingIds?: string[];
  scanId?: string;
  format?: 'html' | 'pdf';
}

export async function exportFindingsReport(
  payload: FindingsReportRequest
): Promise<ReportExportResponse> {
  return request<ReportExportResponse>('/reports/export', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      finding_ids: payload.findingIds ?? [],
      scan_id: payload.scanId,
      format: payload.format ?? 'pdf'
    })
  });
}

export async function createJiraTicket(payload: {
  findingId: string;
  projectKey: string;
  issueType: string;
  summary: string;
  description?: string;
}): Promise<FindingTicket> {
  return request<FindingTicket>('/tickets/jira', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      finding_id: payload.findingId,
      project_key: payload.projectKey,
      issue_type: payload.issueType,
      summary: payload.summary,
      description: payload.description
    })
  });
}

export async function createGitHubTicket(payload: {
  findingId: string;
  repository: string;
  title: string;
  body?: string;
}): Promise<FindingTicket> {
  return request<FindingTicket>('/tickets/github', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      finding_id: payload.findingId,
      repository: payload.repository,
      title: payload.title,
      body: payload.body
    })
  });
}

export async function fetchTargets(): Promise<Target[]> {
  const payload = await request<ApiCollectionResponse<Target[]>>('/targets');
  return payload.data;
}

export interface CreateTargetPayload {
  name: string;
  scope: string;
  is_authorized: boolean;
}

export async function createTarget(payload: CreateTargetPayload): Promise<Target> {
  return request<Target>('/targets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
}

export interface CreateScanPayload {
  target_id: string;
  scanner: string;
  parameters?: Record<string, unknown>;
}

export async function createScan(payload: CreateScanPayload): Promise<Scan> {
  const response = await request<ApiItemResponse<Scan>>('/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      ...payload,
      parameters: payload.parameters ?? {}
    })
  });

  return response.data;
}
