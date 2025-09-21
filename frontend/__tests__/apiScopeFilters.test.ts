import { fetchFindings, fetchFindingsTimeline } from '@/lib/api';

function createJsonResponse(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    headers: new Headers({ 'content-type': 'application/json' }),
    json: async () => body
  } as unknown as Response;
}

describe('controller findings scope filters', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    if (originalFetch) {
      (globalThis as { fetch: typeof fetch }).fetch = originalFetch;
    } else {
      delete (globalThis as { fetch?: typeof fetch }).fetch;
    }
  });

  it('includes scope when requesting findings collections', async () => {
    const fetchMock = jest
      .fn<ReturnType<typeof fetch>, Parameters<typeof fetch>>()
      .mockResolvedValue(createJsonResponse({ data: [], meta: { total: 0, limit: 50, offset: 0 } }));

    (globalThis as { fetch: typeof fetch }).fetch = fetchMock as unknown as typeof fetch;

    await fetchFindings({ scope: 'in_scope' });

    expect(fetchMock).toHaveBeenCalled();
    const [requestUrl] = fetchMock.mock.calls[0];
    expect(requestUrl).toContain('/findings?');
    expect(requestUrl).toContain('scope=in_scope');
  });

  it('includes scope when requesting findings timelines', async () => {
    const fetchMock = jest
      .fn<ReturnType<typeof fetch>, Parameters<typeof fetch>>()
      .mockResolvedValue(createJsonResponse({ data: [] }));

    (globalThis as { fetch: typeof fetch }).fetch = fetchMock as unknown as typeof fetch;

    await fetchFindingsTimeline({ scope: 'mixed' });

    expect(fetchMock).toHaveBeenCalled();
    const [requestUrl] = fetchMock.mock.calls[0];
    expect(requestUrl).toContain('/findings/timeline?');
    expect(requestUrl).toContain('scope=mixed');
  });
});
