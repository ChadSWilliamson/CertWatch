/**
 * uptime-check.mjs
 * -----------------------------------------------------------------
 * Checks whether a website is actually up and responding.
 *
 * "Up" means: the site answered, and didn't return a server error
 * (a 5xx status). A 404 counts as "up" (the server is alive, it
 * just doesn't have that page) — only a true server failure or a
 * total non-response counts as "down".
 */

export async function checkUptime(hostname, timeoutMs = 10000) {
  const url = `https://${hostname}`;
  try {
    const res = await fetch(url, {
      method: "GET",
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "follow",
    });
    return {
      hostname,
      up: res.status < 500,
      statusCode: res.status,
    };
  } catch (err) {
    // Covers timeouts, DNS failures, connection refused, etc.
    return {
      hostname,
      up: false,
      statusCode: null,
      error: err.message,
    };
  }
}
