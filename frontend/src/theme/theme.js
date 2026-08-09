import { createTheme } from '@mui/material/styles';

const theme = createTheme({
  palette: {
    mode: 'dark',
    background: {
      default: '#0A0E1A',
      paper: '#111827',
    },
    primary: {
      main: '#00D4FF',
      contrastText: '#0A0E1A',
    },
    secondary: {
      main: '#3B82F6',
      contrastText: '#FFFFFF',
    },
    error: {
      main: '#FF3B5C',
    },
    warning: {
      main: '#FFB020',
    },
    success: {
      main: '#00E68A',
    },
    text: {
      primary: '#E5E7EB',
      secondary: '#9CA3AF',
    },
    divider: '#1F2937',

    accent: {
      cyan: '#00D4FF',
      blue: '#3B82F6',
      green: '#00E68A',
      red: '#FF3B5C',
      purple: '#A855F7',
      orange: '#FF8A3D',
      amber: '#FFB020',
    },
  },
  typography: {
    fontFamily: "'Inter', sans-serif",
    h1: { fontFamily: "'Inter', sans-serif", fontWeight: 700 },
    h2: { fontFamily: "'Inter', sans-serif", fontWeight: 700 },
    h3: { fontFamily: "'Inter', sans-serif", fontWeight: 700 },
    h4: { fontFamily: "'Inter', sans-serif", fontWeight: 700 },
    h5: { fontFamily: "'Inter', sans-serif", fontWeight: 500 },
    h6: { fontFamily: "'Inter', sans-serif", fontWeight: 500 },
    button: { fontFamily: "'Inter', sans-serif", fontWeight: 600, textTransform: 'none' },
  },
  shape: {
    borderRadius: 6,
  },
});

export default theme;