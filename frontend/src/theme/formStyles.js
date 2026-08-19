/**
 * Shared styling for the console-style form fields on the public pages.
 *
 * It used to be exported from LoginPage.jsx, which two other pages then
 * imported — so a page module was the home of something no page owned, and
 * Vite's fast refresh gave up on the file for exporting a non-component.
 */

export const consoleField = {
  '& .MuiOutlinedInput-root': {
    backgroundColor: '#F4F5F7',
    borderRadius: 1.5,
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: 13,
    transition: 'all 0.22s',
    '& fieldset': { borderColor: '#E2E5E9' },
    '&:hover fieldset': { borderColor: '#C7CCD2' },
    '&.Mui-focused': { backgroundColor: 'rgba(7,110,124,0.05)' },
    '&.Mui-focused fieldset': {
      borderColor: 'rgba(7,110,124,0.60)',
      borderWidth: '1px',
    },
  },
  // Placeholder text is exempt from the 4.5:1 rule only when it duplicates a
  // visible label. These fields carry real hints ("as per service record",
  // "e.g. INV-0042"), so they are held to the same contrast as body text.
  '& input::placeholder': { color: '#5A6068', opacity: 1 },
};
