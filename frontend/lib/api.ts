import { controllerApiKey, controllerBaseUrl, controllerJwt } from './config';
import type { Finding, Scan } from './types';

type ApiCollectionResponse<T> = {
  data: T;
};

type ApiItemResponse<T> = {
  data: T;
};

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

async function request<T>(path: string): Promise<T> {
  const url = `${controllerBaseUrl.replace(/\/$/, '')}${path}`;
  const response = await fetch(url, {
    method: 'GET',
    headers: buildAuthHeaders(),
    cache: 'no-store'
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(
      `Controller request to ${url} failed with ${response.status}: ${message}`
    );
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
