import type { UiError } from '../api/types';

const SCHEMA_DUMP_PATTERNS = [
  /violates\s+[^\s]*schema\.json/i,
  /does not satisfy the contract/i,
  /'pattern'\s*:/,
  /is not valid under any of the given schemas/i,
  /is valid under each of/i,
  /#\/\$defs\//,
];

export function summarizeOperatorError(uiError: UiError): {
  summary: string;
  technicalDetail?: string;
} {
  const raw = (uiError.message || '').trim();
  const isSchemaDump = SCHEMA_DUMP_PATTERNS.some((re) => re.test(raw));
  const isVeryLong = raw.length > 220 || raw.includes('\n');

  if (!isSchemaDump && !isVeryLong) {
    return { summary: raw };
  }

  let summary: string;
  if (/graph read model violates/i.test(raw) || (uiError.path && /\/graph(?:\?|$)/.test(uiError.path))) {
    summary =
      'Không thể dựng đồ thị tài sản vì dữ liệu trả về từ máy chủ không khớp hợp đồng (schema).';
  } else if (/violates\s+[^\s]*schema/i.test(raw)) {
    summary = 'Dữ liệu phản hồi từ máy chủ không khớp hợp đồng (schema).';
  } else if (/does not satisfy/i.test(raw)) {
    summary = 'Yêu cầu không hợp lệ theo hợp đồng API.';
  } else if (uiError.status !== undefined && uiError.status >= 500) {
    summary = 'Máy chủ gặp lỗi nội bộ khi xử lý yêu cầu.';
  } else {
    summary = `${raw.slice(0, 180).trimEnd()}…`;
  }

  return {
    summary,
    technicalDetail: raw,
  };
}
