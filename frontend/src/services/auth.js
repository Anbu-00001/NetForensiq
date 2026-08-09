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

export function logout() {
  sessionStorage.clear();
  window.location.href = '/login';
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