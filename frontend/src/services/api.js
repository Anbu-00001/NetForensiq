import axios from 'axios';

import { API_BASE } from './apiBase';

const api = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
});

// Attach access token to every outgoing request
api.interceptors.request.use((config) => {
  const token = sessionStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Auto-refresh expired access tokens
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;

    // Never auto-redirect on auth endpoints — let the page show its own error
    const isAuthEndpoint =
      original?.url?.includes('/auth/login') ||
      original?.url?.includes('/auth/register');

    if (error.response?.status === 401 && !original._retry && !isAuthEndpoint) {
      original._retry = true;
      const refresh = sessionStorage.getItem('refresh_token');

      if (refresh) {
        try {
          const res = await axios.post(`${API_BASE}/auth/login/refresh/`, { refresh });
          sessionStorage.setItem('access_token', res.data.access);
          if (res.data.refresh) {
            sessionStorage.setItem('refresh_token', res.data.refresh);
          }
          original.headers.Authorization = `Bearer ${res.data.access}`;
          return api(original);
        } catch {
          sessionStorage.clear();
          window.location.href = '/login';
        }
      } else {
        sessionStorage.clear();
        window.location.href = '/login';
      }
    }

    // Rate limiting is a real answer, not a failure to answer. Without this a
    // 429 reached the page as a bare AxiosError and every caller rendered
    // "Request failed" — or, where a caller forgot to catch, nothing at all.
    if (error.response?.status === 429) {
      const retry = error.response.headers?.['retry-after'];
      error.friendlyMessage =
        'Too many requests — this endpoint is rate limited.'
        + (retry ? ` Try again in about ${Math.ceil(Number(retry) / 60)} minute(s).` : '');
    }

    return Promise.reject(error);
  }
);

/** The clearest thing we can say about a failed request. */
export function describeError(error, fallback = 'Request failed.') {
  return (
    error?.friendlyMessage
    ?? error?.response?.data?.detail
    ?? (error?.message === 'Network Error'
      ? 'Could not reach the API. Is the backend running?'
      : null)
    ?? fallback
  );
}

export default api;