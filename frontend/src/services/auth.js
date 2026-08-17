import api from './api';

export async function login(username, password) {
  const res = await api.post('/auth/login/', { username, password });
  sessionStorage.setItem('access_token', res.data.access);
  sessionStorage.setItem('refresh_token', res.data.refresh);
  sessionStorage.setItem('user', JSON.stringify(res.data.user));
  return res.data.user;
}

export async function register(payload) {
  const res = await api.post('/auth/register/', payload);
  return res.data;
}

export async function logout() {
  // Tell the server first, so the refresh token is blacklisted and the sign-out
  // is recorded in the audit log. Clearing sessionStorage alone left the token
  // valid for its full day and left no trace that the session ended.
  //
  // A failure here must not strand the officer on a page they think they have
  // left, so the local session is cleared regardless.
  try {
    const refresh = sessionStorage.getItem('refresh_token');
    await api.post('/auth/logout/', refresh ? { refresh } : {});
  } catch {
    // Offline, expired, or already invalid — signing out locally still stands.
  } finally {
    sessionStorage.clear();
    window.location.href = '/login';
  }
}

export function getCurrentUser() {
  const raw = sessionStorage.getItem('user');
  return raw ? JSON.parse(raw) : null;
}

export function isAuthenticated() {
  return !!sessionStorage.getItem('access_token');
}

export async function checkApprovalStatus(username, badgeId) {
  const res = await api.post('/auth/status/', {
    username,
    badge_id: badgeId,
  });
  return res.data;
}