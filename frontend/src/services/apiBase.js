/**
 * Where the API lives.
 *
 * One definition, because there were three: services/api.js, services/engine.js
 * and the e2e harness each had their own.
 *
 * The production default is same-origin `/api`, not `http://127.0.0.1:8000/api`.
 * A build shipped without VITE_API_BASE used to call the *viewer's* localhost —
 * every request failing in a way that looks like the server is down rather than
 * like a misconfigured build. Same-origin is what a deployment behind a reverse
 * proxy actually wants, and when it is wrong it is wrong visibly.
 */

const configured = import.meta.env.VITE_API_BASE;

function resolve() {
  if (configured) return configured;

  if (import.meta.env.PROD) {
    // Loud, because a production build should not be guessing.
    console.warn(
      'VITE_API_BASE was not set at build time; falling back to same-origin /api.',
    );
    return `${window.location.origin}/api`;
  }
  return 'http://127.0.0.1:8000/api';
}

export const API_BASE = resolve();
