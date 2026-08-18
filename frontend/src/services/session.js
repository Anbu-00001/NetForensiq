/**
 * Who is signed in, and what they are cleared to do.
 *
 * The clearance model is enforced on the server — a viewer's triage request
 * comes back 403. But an interface that renders a Confirm button which always
 * fails is a fake affordance, and this project's second ground rule is that if
 * a control is rendered, it does something.
 *
 * The signed-in user is cached in sessionStorage at login. It is re-fetched
 * from /auth/me/ when that cache is missing — a session restored from tokens
 * alone otherwise has no idea what role it holds, and "unknown role" must not
 * quietly become "full access".
 */
import { useEffect, useState } from 'react';

import api from './api';
import { getCurrentUser } from './auth';

let inFlight = null;

export async function fetchCurrentUser() {
  const cached = getCurrentUser();
  if (cached) return cached;

  if (!inFlight) {
    inFlight = api.get('/auth/me/')
      .then((r) => {
        sessionStorage.setItem('user', JSON.stringify(r.data));
        return r.data;
      })
      .catch(() => null)
      .finally(() => { inFlight = null; });
  }
  return inFlight;
}

/**
 * `null` while unknown — deliberately distinct from "known to be a viewer".
 * Callers render nothing consequential until it resolves, so a slow request
 * cannot briefly expose controls the account is not cleared for.
 */
export function useCurrentUser() {
  const [user, setUser] = useState(() => getCurrentUser());

  useEffect(() => {
    if (user) return undefined;
    let live = true;
    fetchCurrentUser().then((u) => { if (live) setUser(u); });
    return () => { live = false; };
  }, [user]);

  return user;
}

/**
 * True only when the account is known to hold investigator clearance or above
 * *and* has been approved. Unknown resolves to false: the safe direction is
 * showing an officer fewer buttons than they are entitled to, not more.
 */
export function canActOnEvidence(user) {
  if (!user) return false;
  if (!user.is_approved) return false;
  return user.role === 'investigator' || user.role === 'admin';
}
