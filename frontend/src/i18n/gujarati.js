/**
 * Gujarati glosses for the legal terms this interface uses.
 *
 * Not a translation of the application. This is a glossary: the handful of
 * terms a Gujarati-medium officer or magistrate would look for, beside their
 * English originals, so the artefacts this system produces can be read by
 * someone who works in Gujarati.
 *
 * Why here and not on the certificate PDF
 * ---------------------------------------
 * The PDF renderer does not shape complex scripts — it places glyphs in
 * codepoint order, so `અધિનિયમ` comes out as `અધનિયિમ` and `સ્થળ` loses its
 * virama entirely. Mangled Gujarati on a statutory declaration is worse than
 * English only. A browser shapes the script correctly, so the glossary lives
 * where it renders properly. The evidence for that decision is in
 * research/99_GUJARAT_FIT.md.
 *
 * Terms follow Gujarat Police and Gujarati legal usage — `મુદ્દામાલ` is the
 * word the state's own case-property registers use for a seized exhibit, not a
 * literal rendering of "exhibit".
 *
 * The English text remains authoritative everywhere. These are a reading aid.
 */

export const GUJARATI = {
  // Statute
  act: 'ભારતીય સાક્ષ્ય અધિનિયમ, ૨૦૨૩',
  certificate: 'પ્રમાણપત્ર',
  schedule: 'અનુસૂચિ',
  section: 'કલમ ૬૩(૪)(ગ)',

  // Evidence handling
  evidenceRegister: 'મુદ્દામાલ રજિસ્ટર',
  exhibitNumber: 'મુદ્દામાલ ક્રમાંક',
  chainOfCustody: 'કબજાની સાંકળ',
  hashValue: 'હેશ મૂલ્ય',
  sealed: 'સીલબંધ',
  integrityFailed: 'અખંડિતતા નિષ્ફળ',

  // Roles on the certificate
  partA: 'ભાગ ક — ઉપકરણના પ્રભારી વ્યક્તિ',
  partB: 'ભાગ ખ — નિષ્ણાત',

  // Findings
  findings: 'તારણો',
  severity: 'ગંભીરતા',
  underReview: 'સમીક્ષા બાકી',

  // Provenance
  notEvidence: 'આ પુરાવો નથી — નિદર્શન માટેની માહિતી',
};

/** `English (ગુજરાતી)` — the form used in headings. */
export const bilingual = (english, key) =>
  (GUJARATI[key] ? `${english} (${GUJARATI[key]})` : english);
