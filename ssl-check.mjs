/**
 * ssl-check.mjs
 * -----------------------------------------------------------------
 * Checks how many days are left on a website's real SSL
 * certificate — the thing that makes the padlock icon show up
 * in a browser.
 *
 * How it works, in plain terms: it opens a secure connection to
 * the site (the same kind your browser opens when you visit an
 * https:// website), reads the certificate the site hands back,
 * and looks at the "valid until" date printed on it.
 */

import tls from "node:tls";

export function checkSSLExpiry(hostname, port = 443) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host: hostname, port, servername: hostname, timeout: 8000 },
      () => {
        const cert = socket.getPeerCertificate();
        socket.end();
        if (!cert || !cert.valid_to) {
          return reject(new Error(`No certificate returned for ${hostname}`));
        }
        const expiresAt = new Date(cert.valid_to);
        const daysLeft = Math.ceil((expiresAt - Date.now()) / 86_400_000);
        resolve({ hostname, expiresAt, daysLeft });
      }
    );
    socket.on("error", reject);
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error(`TLS connection to ${hostname} timed out`));
    });
  });
}
