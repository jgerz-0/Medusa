import { cookies, headers } from 'next/headers';
import { readSession } from '@/lib/auth';
import { controllerApiKey, controllerBaseUrl, controllerJwt } from './config';
import type {
  AnomalyEvent,
  Finding,
  FindingComment,
  FindingTimelineEvent,
  FindingsTimelineBucket,
  ReconDiscovery,
  ReconObservation,
  ReconRun,
  ReportExportResponse,
  Scan,
  Target,
  FindingTicket
} from './types';

interface PaginationMetadata {
  total: number;
  limit: number;
  offset: number;
}

type ApiCollectionResponse<T> = {
  data: T;
  meta?: PaginationMetadata;
};

type ApiItemResponse<T> = {
  data: T;
};

interface FindingItemResponse extends ApiItemResponse<Finding> {}

interface FindingCollectionResponse extends ApiCollectionResponse<Finding[]> {
  workflow_counts: WorkflowCounts;
}

interface ReconDiscoveryCollectionResponse
  extends ApiCollectionResponse<ReconDiscovery[]> {}

interface ReconRunCollectionResponse extends ApiCollectionResponse<ReconRun[]> {}

interface ReconObservationCollectionResponse
  extends ApiCollectionResponse<ReconObservation[]> {}

interface AnomalyCollectionResponse extends ApiCollectionResponse<AnomalyEvent[]> {}

interface AnomalyItemResponse extends ApiItemResponse<AnomalyEvent> {}

export interface PaginationState {
  page: number;
  pageSize: number;
  total: number;
}

export interface PaginatedResponse<T> {
  data: T;
  pagination: PaginationState | null;
  workflowCounts?: WorkflowCounts;
}

export interface PaginationQuery {
  page?: number;
  pageSize?: number;
}

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
  page?: number;
  pageSize?: number;
}

export interface WorkflowCounts {
  pending_validation: number;
  open: number;
  invalidated: number;
  acknowledged: number;
  resolved: number;
}

export interface AnomalyQuery extends PaginationQuery {
  type?: string;
  actor?: string;
  source?: string;
  from?: string;
  to?: string;
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

function deserializePagination(meta?: PaginationMetadata): PaginationState | null {
  if (!meta) {
    return null;
  }

  const pageSize = Number.isFinite(meta.limit) && meta.limit > 0 ? Math.trunc(meta.limit) : 1;
  const offset = Number.isFinite(meta.offset) && meta.offset >= 0 ? Math.trunc(meta.offset) : 0;
  const total = Number.isFinite(meta.total) && meta.total >= 0 ? Math.trunc(meta.total) : 0;
  const page = pageSize > 0 ? Math.floor(offset / pageSize) + 1 : 1;

  return {
    page,
    pageSize,
    total
  } satisfies PaginationState;
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

function sanitizeHeader(value: string | null): string | undefined {
  if (!value) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function parseBearerHeader(value: string | null): string | undefined {
  const normalized = sanitizeHeader(value);
  if (!normalized) {
    return undefined;
  }
  if (!normalized.toLowerCase().startsWith('bearer ')) {
    return undefined;
  }
  const token = normalized.slice(7).trim();
  return token.length > 0 ? token : undefined;
}

function resolveRequestHeaders(): Headers | null {
  try {
    return headers();
  } catch {
    return null;
  }
}

async function resolveSessionCredentials(): Promise<{ bearerToken?: string; apiKey?: string }> {
  const requestHeaders = resolveRequestHeaders();
  if (requestHeaders) {
    const headerToken = parseBearerHeader(requestHeaders.get('authorization'));
    if (headerToken) {
      return { bearerToken: headerToken };
    }

    const headerApiKey = sanitizeHeader(requestHeaders.get('x-api-key'));
    if (headerApiKey) {
      return { apiKey: headerApiKey };
    }
  }

  try {
    const store = cookies();
    const session = await readSession(store);
    if (session?.accessToken) {
      return { bearerToken: session.accessToken };
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : '';
    if (!message.includes('outside a request scope')) {
      console.warn('Failed to resolve session credentials', error);
    }
  }

  if (controllerApiKey) {
    return { apiKey: controllerApiKey };
  }
  if (controllerJwt) {
    return { bearerToken: controllerJwt };
  }
  return {};
}

async function buildAuthHeaders(): Promise<HeadersInit> {
  const headers: Record<string, string> = {
    Accept: 'application/json'
  };

  const { bearerToken, apiKey } = await resolveSessionCredentials();

  if (bearerToken) {
    headers['Authorization'] = `Bearer ${bearerToken}`;
  }

  if (apiKey) {
    headers['X-API-Key'] = apiKey;
    if (!headers['Authorization']) {
      headers['Authorization'] = `Bearer ${apiKey}`;
    }
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
  const baseHeaders = normalizeHeaders(await buildAuthHeaders());
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

export interface FetchScansParams extends PaginationQuery {
  targetId?: string;
}

export async function fetchScans(params?: FetchScansParams): Promise<PaginatedResponse<Scan[]>> {
  const limit = params?.pageSize ? Math.max(1, Math.trunc(params.pageSize)) : undefined;
  const page = params?.page ? Math.max(1, Math.trunc(params.page)) : undefined;
  const offset = page && limit ? (page - 1) * limit : undefined;

  const path = buildPath('/scans', {
    target_id: params?.targetId,
    limit: limit !== undefined ? `${limit}` : undefined,
    offset: offset !== undefined ? `${offset}` : undefined
  });
  const payload = await request<ApiCollectionResponse<Scan[]>>(path);
  return {
    data: payload.data,
    pagination: deserializePagination(payload.meta)
  } satisfies PaginatedResponse<Scan[]>;
}

export async function fetchFindings(query?: FindingsQuery): Promise<PaginatedResponse<Finding[]>> {
  const limit = query?.pageSize ? Math.max(1, Math.trunc(query.pageSize)) : undefined;
  const page = query?.page ? Math.max(1, Math.trunc(query.page)) : undefined;
  const offset = page && limit ? (page - 1) * limit : undefined;

  const path = buildPath('/findings', {
    target_id: query?.targetId,
    scan_id: query?.scanId,
    severity: query?.severity,
    status: query?.status,
    tag: query?.tag,
    assigned_to: query?.assignedTo,
    from: query?.from,
    to: query?.to,
    scope: query?.scope,
    limit: limit !== undefined ? `${limit}` : undefined,
    offset: offset !== undefined ? `${offset}` : undefined
  });
  const payload = await request<FindingCollectionResponse>(path);
  return {
    data: payload.data,
    pagination: deserializePagination(payload.meta),
    workflowCounts: payload.workflow_counts
  } satisfies PaginatedResponse<Finding[]>;
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
  query?: Omit<FindingsQuery, 'page' | 'pageSize'>
): Promise<FindingsTimelineBucket[]> {
  const path = buildPath('/findings/timeline', {
    target_id: query?.targetId,
    scan_id: query?.scanId,
    severity: query?.severity,
    status: query?.status,
    scope: query?.scope,
    tag: query?.tag,
    assigned_to: query?.assignedTo,
    from: query?.from,
    to: query?.to
  });
  const payload = await request<ApiCollectionResponse<FindingsTimelineBucket[]>>(path);
  return payload.data;
}

export async function fetchAnomalies(
  query?: AnomalyQuery
): Promise<PaginatedResponse<AnomalyEvent[]>> {
  const limit = query?.pageSize ? Math.max(1, Math.trunc(query.pageSize)) : undefined;
  const page = query?.page ? Math.max(1, Math.trunc(query.page)) : undefined;
  const offset = page && limit ? (page - 1) * limit : undefined;

  const path = buildPath('/anomalies', {
    type: query?.type,
    actor: query?.actor,
    source: query?.source,
    from: query?.from,
    to: query?.to,
    limit: limit ? `${limit}` : undefined,
    offset: offset !== undefined ? `${offset}` : undefined
  });

  const payload = await request<AnomalyCollectionResponse>(path);
  return {
    data: payload.data,
    pagination: deserializePagination(payload.meta)
  } satisfies PaginatedResponse<AnomalyEvent[]>;
}

export async function fetchAnomaly(id: string): Promise<AnomalyEvent> {
  const payload = await request<AnomalyItemResponse>(`/anomalies/${id}`);
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

export interface ReportExportsQuery extends PaginationQuery {
  scanId?: string;
  findingId?: string;
  limit?: number;
  offset?: number;
}

export async function fetchReportExports(
  query?: ReportExportsQuery
): Promise<PaginatedResponse<ReportExportResponse[]>> {
  const requestedLimit =
    typeof query?.limit === 'number' && Number.isFinite(query.limit) && query.limit > 0
      ? Math.trunc(query.limit)
      : undefined;
  const requestedPageSize =
    typeof query?.pageSize === 'number' && Number.isFinite(query.pageSize) && query.pageSize > 0
      ? Math.trunc(query.pageSize)
      : undefined;
  const limit = requestedLimit ?? requestedPageSize;

  const requestedOffset =
    typeof query?.offset === 'number' && Number.isFinite(query.offset) && query.offset >= 0
      ? Math.trunc(query.offset)
      : undefined;
  const requestedPage =
    typeof query?.page === 'number' && Number.isFinite(query.page) && query.page > 0
      ? Math.trunc(query.page)
      : undefined;

  const computedOffset =
    requestedOffset !== undefined
      ? requestedOffset
      : requestedPage !== undefined && limit !== undefined
        ? (requestedPage - 1) * limit
        : undefined;

  const path = buildPath('/reports/export', {
    scan_id: query?.scanId,
    findingId: query?.findingId,
    limit: limit !== undefined ? `${limit}` : undefined,
    offset: computedOffset !== undefined ? `${computedOffset}` : undefined
  });
  const payload = await request<ReportExportCollectionResponse>(path);
  return {
    data: payload.data ?? [],
    pagination: deserializePagination(payload.meta)
  } satisfies PaginatedResponse<ReportExportResponse[]>;
}

export async function downloadReportArtifact(reportId: string): Promise<Response> {
  const url = `${controllerBaseUrl.replace(/\/$/, '')}/reports/${reportId}`;
  const headers = normalizeHeaders(await buildAuthHeaders());
  const response = await fetch(url, { cache: 'no-store', headers });
  if (!response.ok) {
    const detail = await response.text();
    const message = detail && detail.trim().length > 0 ? detail : `Controller returned ${response.status} for report download.`;
    throw new ControllerError(message, response.status, detail);
  }
  return response;
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

export async function fetchReconDiscoveries(status?: string): Promise<ReconDiscovery[]> {
  const path = buildPath('/recon/discoveries', { status });
  const payload = await request<ReconDiscoveryCollectionResponse>(path);
  return payload.data;
}

export async function fetchReconRuns(limit?: number): Promise<ReconRun[]> {
  const path = buildPath('/recon/runs', {
    limit: typeof limit === 'number' ? `${limit}` : undefined
  });
  const payload = await request<ReconRunCollectionResponse>(path);
  return payload.data;
}

export async function fetchReconRunObservations(runId: string): Promise<ReconObservation[]> {
  const payload = await request<ReconObservationCollectionResponse>(
    `/recon/runs/${runId}/observations`
  );
  return payload.data;
}

export async function promoteDiscovery(payload: {
  discoveryId: string;
  targetName: string;
  scope?: string | null;
}): Promise<Target> {
  const body: Record<string, unknown> = {
    target_name: payload.targetName
  };
  const scopeValue = payload.scope?.trim();
  if (scopeValue) {
    body.scope = scopeValue;
  }

  return request<Target>(`/recon/discoveries/${payload.discoveryId}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
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
