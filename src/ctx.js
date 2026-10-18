import { sniffBody, emptyHeaders, parseRawResponse, parseSetCookie } from './parse.js';
import { decodeBody } from './exec.js';

/**
 * Susun konteks analisis dari hasil runCurl: hop final, body terdekompresi,
 * info jenis konten, dan opsional probe TLS.
 */
export function buildCtxFromRun(run, { tls = null, tlsProbed = false } = {}) {
  const final = run.final;
  const headers = final?.headers ?? emptyHeaders();
  const contentType = headers.get('content-type') ?? '';
  const contentEncoding = headers.get('content-encoding');
  const rawBuffer = final?.bodyBuffer ?? Buffer.alloc(0);
  const { buffer, decoded, failed } = decodeBody(rawBuffer, contentEncoding);
  const text = buffer.toString('utf8');
  const bodyInfo = sniffBody(text, contentType);
  return {
    mode: 'run',
    requestedUrl: run.requestedUrl,
    url: final?.url ?? run.requestedUrl,
    method: final?.method ?? 'GET',
    follow: false,
    insecure: false,
    hops: run.hops ?? [],
    final: final
      ? { ...final, headers, bodyInfo, bodySize: buffer.length, bodyRawSize: rawBuffer.length, bodyText: text, bodyBuffer: buffer }
      : null,
    headers,
    bodyInfo,
    bodySize: buffer.length,
    bodyRawSize: rawBuffer.length,
    bodyText: text,
    metrics: final?.metrics ?? null,
    contentEncoding,
    decode: { decoded, failed },
    tls,
    tlsProbed,
    error: run.error ?? null,
    stderr: run.stderr ?? '',
    hopsCount: run.hops?.length ?? 0,
  };
}

/**
 * Susun konteks dari output mentah (mode analyze / stdin): tangkap blok
 * header, body setelah blok terakhir, dan metrik opsional via --metrics.
 */
export function buildCtxFromRaw(raw, { url = null, tls = null, tlsProbed = false, method = 'GET' } = {}) {
  const parsed = parseRawResponse(raw);
  const headers = parsed.headers ?? emptyHeaders();
  const contentType = headers.get('content-type') ?? '';
  const contentEncoding = headers.get('content-encoding');
  const rawBuffer = Buffer.from(parsed.bodyText ?? '', 'utf8');
  const { buffer, decoded, failed } = decodeBody(rawBuffer, contentEncoding);
  const text = buffer.toString('utf8');
  const bodyInfo = sniffBody(text, contentType);
  const code = headers.code || 0;
  const hop = {
    index: 0,
    url: url ?? '(output tempel)',
    method,
    status: code,
    statusText: headers.statusText,
    httpVersion: headers.httpVersion || '1.1',
    headers,
    metrics: null,
    bodyBuffer: buffer,
    stderr: '',
  };
  return {
    mode: 'analyze',
    requestedUrl: url,
    url: url ?? '(output tempel)',
    method,
    follow: false,
    insecure: false,
    hops: [hop],
    final: { ...hop, headers, bodyInfo, bodySize: buffer.length, bodyRawSize: rawBuffer.length, bodyText: text },
    headers,
    bodyInfo,
    bodySize: buffer.length,
    bodyRawSize: rawBuffer.length,
    bodyText: text,
    metrics: null,
    contentEncoding,
    decode: { decoded, failed },
    tls,
    tlsProbed,
    error: null,
    stderr: '',
    hopsCount: 1,
  };
}

export function cookiesOf(headers) {
  return headers.getAll('set-cookie').map((raw) => parseSetCookie(raw));
}
