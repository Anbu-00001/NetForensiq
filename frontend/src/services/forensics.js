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

export const analyseSession = (id) =>
  api.post(`/sessions/${id}/analyse/`).then((r) => r.data);

export const listFlows = (params = {}) =>
  api.get('/flows/', { params }).then((r) => r.data);

export const getFlow = (id) =>
  api.get(`/flows/${id}/`).then((r) => r.data);

export const listDetections = (params = {}) =>
  api.get('/detections/', { params }).then((r) => r.data);

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

/** DRF pagination returns {results: []}; plain lists come back bare. */
export const unwrap = (data) => (Array.isArray(data) ? data : data?.results ?? []);

export const formatBytes = (bytes) => {
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
  critical: '#FF3B5C',
  high: '#FF6A2B',
  medium: '#FFB020',
  low: '#00A8FF',
};
