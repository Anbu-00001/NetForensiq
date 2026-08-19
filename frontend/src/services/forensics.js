import api from './api';

/**
 * Every figure rendered in the UI comes from one of these calls.
 * If a number appears on screen and is not traceable to this file, it is a bug.
 */

export const listSessions = () =>
  api.get('/sessions/').then((r) => r.data);

export const getSession = (id) =>
  api.get(`/sessions/${id}/`).then((r) => r.data);

export const getSessionSummary = (id) =>
  api.get(`/sessions/${id}/summary/`).then((r) => r.data);

export const getSessionTimeline = (id) =>
  api.get(`/sessions/${id}/timeline/`).then((r) => r.data);

// The capture drawn as a diagram rather than counted. See
// components/graph/NetworkGraph.jsx for why a picture answers a question the
// figures cannot.
//
// `focus` decides who is in the picture: 'flagged' (the default) draws the
// implicated hosts and the machines they talked to, folding the quiet
// remainder into one circle; 'all' draws everything.
export const getSessionGraph = (id, { nodes, focus } = {}) =>
  api.get(`/sessions/${id}/graph/`, {
    params: { ...(nodes ? { nodes } : {}), ...(focus ? { focus } : {}) },
  }).then((r) => r.data);

// The findings against each implicated host, assembled into kill-chain order.
//
// A separate call from the graph rather than a field on it: the diagram is
// about who talked to whom and this is about what happened in what order, and
// a reader who never scrolls to the second should not have paid for it.
export const getSessionScenario = (id, { minFindings } = {}) =>
  api.get(`/sessions/${id}/scenario/`, {
    params: minFindings ? { min_findings: minFindings } : {},
  }).then((r) => r.data);

export const analyseSession = (id) =>
  api.post(`/sessions/${id}/analyse/`).then((r) => r.data);

export const listFlows = (params = {}) =>
  api.get('/flows/', { params }).then((r) => r.data);

export const getFlow = (id) =>
  api.get(`/flows/${id}/`).then((r) => r.data);

// Rebuilt on demand from the sealed exhibit and never cached server-side, so
// this is a slow call by design — it reads the capture. See
// backend/capture/protocols.py for why decoded content is not kept in a table.
export const getFlowTranscript = (id) =>
  api.get(`/flows/${id}/transcript/`).then((r) => r.data);

export const listDetections = (params = {}) =>
  api.get('/detections/', { params }).then((r) => r.data);

/**
 * Every finding for a session, following DRF's pagination.
 *
 * The page used to call listDetections() with no session filter and no paging,
 * then render data.results — the first 50 rows of every session pooled
 * together — while the "awaiting review" chip counted only what had loaded.
 * On the real server capture that is 50 of 307, presented as the whole set.
 */
export const listAllDetections = async (params = {}) => {
  const collected = [];
  // Ask for a large page. The default of 50 meant seven sequential round trips
  // for one capture's findings — slow, and enough on its own to eat into the
  // hourly request budget. The server caps this at 500, so paging still works
  // for anything larger.
  const first = { page_size: 500, ...params };
  let response = await api.get('/detections/', { params: first }).then((r) => r.data);

  if (Array.isArray(response)) return response;

  collected.push(...(response.results ?? []));
  while (response.next) {
    response = await api.get(response.next).then((r) => r.data);
    collected.push(...(response.results ?? []));
  }
  return collected;
};

export const triageDetection = (id, status, note = '') =>
  api.post(`/detections/${id}/triage/`, { status, note }).then((r) => r.data);

export const listThresholds = () =>
  api.get('/detections/thresholds/').then((r) => r.data);

export const listEvidence = () =>
  api.get('/evidence/').then((r) => r.data);

export const getCustodyChain = (id) =>
  api.get(`/evidence/${id}/custody/`).then((r) => r.data);

export const verifyEvidence = (id) =>
  api.post(`/evidence/${id}/verify/`).then((r) => r.data);

export const issueCertificate = (id, payload) =>
  api.post(`/evidence/${id}/certificate/`, payload).then((r) => r.data);

export const listCertificates = () =>
  api.get('/certificates/').then((r) => r.data);

export const signCertificatePartB = (id, payload) =>
  api.post(`/certificates/${id}/sign/`, payload).then((r) => r.data);

/**
 * Download the rendered s.63 certificate.
 *
 * Fetched as a blob through the authenticated client rather than linked
 * directly: the endpoint requires a bearer token, so a plain <a href> would
 * come back 401. The object URL is revoked immediately after the click to
 * avoid leaking it for the lifetime of the page.
 */
export const downloadCertificatePdf = async (id, reference) => {
  const response = await api.get(`/certificates/${id}/pdf/`, {
    responseType: 'blob',
  });
  const url = window.URL.createObjectURL(
    new Blob([response.data], { type: 'application/pdf' }),
  );
  const link = document.createElement('a');
  link.href = url;
  link.download = `${reference || `certificate-${id}`}.pdf`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
};

/** DRF pagination returns {results: []}; plain lists come back bare. */
export const unwrap = (data) => (Array.isArray(data) ? data : data?.results ?? []);

export const formatBytes = (bytes) => {
  // A missing value is not a measured zero. formatCount beside this already
  // returns an em dash; without the same distinction here an absent byte
  // total printed as "0 B" as though it had been observed.
  if (bytes === null || bytes === undefined) return '—';
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** i).toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
};

export const formatCount = (n) => {
  if (n === null || n === undefined) return '—';
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)} M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)} K`;
  return String(n);
};

export const SEVERITY_COLOR = {
  critical: '#B3261E',
  high: '#A84D08',
  medium: '#8A6100',
  low: '#1F3A5F',
};

/**
 * The approval queue. Administrators only — the server refuses anyone else.
 *
 * Approving an officer decides who may touch evidence at all, and it was
 * previously possible only through the Django admin: the one act the system
 * cares most about, happening outside the system.
 */
export const listPendingAccounts = () =>
  api.get('/auth/accounts/pending/').then((r) => r.data);

export const decideAccount = (username, decision) =>
  api.post('/auth/accounts/pending/', { username, decision }).then((r) => r.data);

/**
 * The state of the evidence holding: clock, seal, encryption, case.
 *
 * One call because these are read together — a strip that draws three of the
 * four while the fourth is still in flight is a strip that flickers, and this
 * one sits in an officer's eyeline all day.
 */
export const getEvidencePosture = () =>
  api.get('/evidence/posture/').then((r) => r.data);
