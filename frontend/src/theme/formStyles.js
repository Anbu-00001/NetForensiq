/**
 * Shared styling for the console-style form fields on the public pages.
 *
 * It used to be exported from LoginPage.jsx, which two other pages then
 * imported — so a page module was the home of something no page owned, and
 * Vite's fast refresh gave up on the file for exporting a non-component.
 */

export const consoleField = {
  '& .MuiOutlinedInput-root': {
    backgroundColor: 'rgba(255,255,255,0.03)',
    borderRadius: 1.5,
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: 13,
    transition: 'all 0.22s',
    '& fieldset': { borderColor: 'rgba(255,255,255,0.08)' },
    '&:hover fieldset': { borderColor: 'rgba(255,255,255,0.16)' },
    '&.Mui-focused': { backgroundColor: 'rgba(255,153,51,0.05)' },
    '&.Mui-focused fieldset': {
      borderColor: 'rgba(255,153,51,0.60)',
      borderWidth: '1px',
      boxShadow: '0 0 0 3px rgba(255,153,51,0.14)',
    },
  },
  // Placeholder text is exempt from the 4.5:1 rule only when it duplicates a
  // visible label. These fields carry real hints ("as per service record",
  // "e.g. INV-0042"), so they are held to the same contrast as body text.
  '& input::placeholder': { color: 'rgba(232,236,244,0.55)', opacity: 1 },
};
