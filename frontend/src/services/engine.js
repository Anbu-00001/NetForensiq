/**
 * What the detection engine is, for pages shown before sign-in.
 *
 * The landing and login pages state how many rules exist and which version
 * this is. Those were literals in three places — "Seven deterministic rules",
 * "seven cited rules", "7 RULES, SOURCED OR TAGGED" — plus a hardcoded
 * "NETFORENSIQ v1.0". Adding a rule made all four wrong with nothing to catch
 * it, on the first page a judge sees.
 *
 * /api/engine/ is public precisely because these pages are.
 */
import axios from 'axios';

import { API_BASE } from './apiBase';

export async function getEngineInfo() {
  const { data } = await axios.get(`${API_BASE}/engine/`);
  return data;
}

/**
 * Small words for small numbers, because "9 deterministic rules" mid-sentence
 * reads like a spec sheet and "nine" reads like English.
 */
const WORDS = [
  'zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight',
  'nine', 'ten', 'eleven', 'twelve',
];

export const spellOut = (n) =>
  (typeof n === 'number' && n >= 0 && n < WORDS.length ? WORDS[n] : String(n ?? '—'));
