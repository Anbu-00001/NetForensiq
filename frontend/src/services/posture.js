import { useEffect, useState } from 'react';
import { getEvidencePosture } from './forensics';

/**
 * One poll of `/api/evidence/posture/`, shared by everything that draws it.
 *
 * The endpoint answers in one request on purpose: the facts in the operator
 * strip are read together or not at all, and a strip that draws three rows
 * while a fourth is still in flight is a strip that flickers in the corner of
 * somebody's eye all day until they stop looking at it.
 *
 * That guarantee is only worth anything if the client honours it. Six
 * components each calling the hook must produce **one** request on an interval,
 * not six — otherwise the sidebar is back to six chances at a partial answer,
 * and on a workstation that is also running a capture it is six times the load
 * for no new information.
 *
 * So the state lives here, at module scope, with a subscriber count: the timer
 * starts when the first component mounts and stops when the last one leaves.
 * A late subscriber is served the cached value immediately and then the next
 * tick, so a panel that mounts between polls is never blank.
 */

const REFRESH_MS = 60_000;

let cache = null;
let inFlight = null;
let timer = null;
const listeners = new Set();

function publish() {
  listeners.forEach((fn) => fn(cache));
}

function load() {
  // Collapsed rather than queued: a re-render storm during navigation must not
  // turn into a queue of identical requests against a box that may be busy
  // parsing a capture.
  if (inFlight) return inFlight;
  inFlight = getEvidencePosture()
    .then((data) => {
      cache = data;
      publish();
      return data;
    })
    .catch(() => {
      // The strip is context. A failed poll leaves the last known state on
      // screen rather than blanking the panel — but it must never take the
      // page down, and it must never invent a value to fill the gap.
      return cache;
    })
    .finally(() => { inFlight = null; });
  return inFlight;
}

export function refreshPosture() {
  return load();
}

export function usePosture() {
  // Seeded from the cache at first render rather than set inside the effect:
  // a panel mounting between polls shows the last known state immediately, and
  // does so without a second render pass.
  const [state, setState] = useState(() => cache);

  useEffect(() => {
    listeners.add(setState);
    load();
    if (!timer) timer = setInterval(load, REFRESH_MS);

    return () => {
      listeners.delete(setState);
      if (listeners.size === 0 && timer) {
        clearInterval(timer);
        timer = null;
      }
    };
  }, []);

  return state;
}

export default usePosture;
