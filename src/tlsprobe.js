import tls from 'node:tls';

/**
 * Probe TLS terpisah (koneksi handshake saja, tanpa HTTP) untuk info
 * protokol, sertifikat, dan cipher. Untuk https saja.
 */
export function probeTls(rawUrl, timeoutMs = 5000) {
  return new Promise((resolve) => {
    let u;
    try {
      u = new URL(rawUrl);
    } catch {
      return resolve(null);
    }
    if (u.protocol !== 'https:') return resolve(null);
    const host = u.hostname;
    const port = u.port ? Number(u.port) : 443;
    let done = false;
    const finish = (v) => {
      if (done) return;
      done = true;
      try {
        socket.destroy();
      } catch {
        /* noop */
      }
      resolve(v);
    };
    let socket;
    try {
      socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false });
    } catch (e) {
      return resolve({ error: e.message });
    }
    socket.setTimeout(timeoutMs, () => finish({ error: `timeout ${timeoutMs} ms` }));
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate() ?? {};
      const cipher = typeof socket.getCipher === 'function' ? socket.getCipher() : null;
      const daysLeft = cert.valid_to
        ? Math.floor((Date.parse(cert.valid_to) - Date.now()) / 86400000)
        : null;
      const subjectCN = cert.subject?.CN ?? null;
      const issuerCN = cert.issuer?.CN ?? null;
      finish({
        protocol: socket.getProtocol(),
        cipher: cipher?.name ?? null,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError.message ?? socket.authorizationError) : null,
        subjectCN,
        issuerCN,
        validTo: cert.valid_to ?? null,
        daysLeft,
        selfSigned: Boolean(subjectCN && issuerCN && subjectCN === issuerCN),
      });
    });
    socket.once('error', (e) => finish({ error: e.message, code: e.code }));
  });
}
