import { NextRequest, NextResponse } from 'next/server';
import { downloadReportArtifact, exportFindingsReport } from '@/lib/api';

function parseFormat(value: string | null): 'html' | 'pdf' {
  if (value === 'html') {
    return 'html';
  }
  return 'pdf';
}

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const format = parseFormat(searchParams.get('format'));
  const existingReportId = searchParams.get('reportId');
  const findingIds = searchParams.getAll('findingId');
  const scanId = searchParams.get('scanId') ?? searchParams.get('scan_id') ?? undefined;

  const reportId = existingReportId
    ? existingReportId
    : (
        await exportFindingsReport({
          format,
          findingIds: findingIds.length > 0 ? findingIds : undefined,
          scanId: scanId ?? undefined
        })
      ).report_id;

  const artifact = await downloadReportArtifact(reportId);
  const arrayBuffer = await artifact.arrayBuffer();
  const buffer = Buffer.from(arrayBuffer);
  const contentType = artifact.headers.get('content-type') ?? (format === 'pdf' ? 'application/pdf' : 'text/html; charset=utf-8');
  const checksum = artifact.headers.get('x-report-checksum') ?? '';
  const fileName = `medusa-report-${reportId}.${format}`;

  return new NextResponse(buffer, {
    status: 200,
    headers: {
      'Content-Type': contentType,
      'Content-Disposition': `attachment; filename="${fileName}"`,
      'X-Report-Checksum': checksum
    }
  });
}
