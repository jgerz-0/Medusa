import { NextRequest, NextResponse } from 'next/server';
import { exportFindingsReport } from '@/lib/api';

function parseFormat(value: string | null): 'html' | 'pdf' {
  if (value === 'html') {
    return 'html';
  }
  return 'pdf';
}

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const format = parseFormat(searchParams.get('format'));
  const findingIds = searchParams.getAll('findingId');
  const scanId = searchParams.get('scanId') ?? searchParams.get('scan_id') ?? undefined;

  const payload = await exportFindingsReport({
    format,
    findingIds: findingIds.length > 0 ? findingIds : undefined,
    scanId: scanId ?? undefined
  });

  const buffer = Buffer.from(payload.content, 'base64');
  const fileName = `medusa-report-${payload.report_id}.${format}`;

  return new NextResponse(buffer, {
    status: 200,
    headers: {
      'Content-Type': format === 'pdf' ? 'application/pdf' : 'text/html; charset=utf-8',
      'Content-Disposition': `attachment; filename="${fileName}"`
    }
  });
}
