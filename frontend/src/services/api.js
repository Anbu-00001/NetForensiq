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

    return Promise.reject(error);
  }
);

export default api;