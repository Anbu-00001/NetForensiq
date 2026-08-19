import { useEffect, useState } from 'react';
import { Box, Typography, Button } from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import ShieldOutlinedIcon from '@mui/icons-material/ShieldOutlined';
import LoginIcon from '@mui/icons-material/Login';
import PersonAddAltIcon from '@mui/icons-material/PersonAddAlt';
import RadarIcon from '@mui/icons-material/Radar';
import HubIcon from '@mui/icons-material/Hub';
import GavelIcon from '@mui/icons-material/Gavel';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import { ConsoleBar } from './LoginPage';
import { getEngineInfo, spellOut } from '../services/engine';

const features = [
  { icon: <RadarIcon />, title: 'Explainable Detection', tag: 'CITED THRESHOLDS',
    desc: (engine) => `${spellOut(engine?.rule_count)} deterministic rules for beaconing, DNS tunnelling, port scanning, exfiltration and covert channels. Every threshold carries its source, and values we invented say so.`, color: '#076E7C' },
  { icon: <HubIcon />, title: 'Analyst Triage', tag: 'HUMAN IN THE LOOP',
    desc: 'Nothing is auto-actioned. Each finding states the value observed, the threshold it crossed and where that threshold came from, then waits for an officer to confirm, dismiss or escalate.', color: '#1B6E3C' },
  { icon: <GavelIcon />, title: 'Section 63 Certificate', tag: 'BSA 2023 SCHEDULE',
    desc: 'Generates the certificate prescribed by THE SCHEDULE to the Bharatiya Sakshya Adhiniyam 2023, Parts A and B, with the hash report the Schedule requires enclosed.', color: '#8A6100' },
  { icon: <VerifiedUserIcon />, title: 'Sealed Evidence', tag: 'SHA-256 CUSTODY',
    desc: 'Each exhibit is hashed before anything reads it. The custody log is hash-chained, so an altered or removed entry breaks every later link — tamper-evident, which is what a database table can honestly claim.', color: '#6B4FA8' },
];

function LandingPage() {
  // Counts and version come from the engine, not from prose. A failed fetch
  // leaves them as an em dash rather than falling back to a number that was
  // true when the copy was written.
  const [engine, setEngine] = useState(null);

  useEffect(() => {
    let live = true;
    getEngineInfo()
      .then((info) => { if (live) setEngine(info); })
      .catch(() => {});
    return () => { live = false; };
  }, []);

  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    // Deferred to the next frame rather than set synchronously in the effect:
    // setting state directly in an effect re-renders immediately and the
    // entry transition never runs, because the element is mounted with its
    // final styles already applied.
    const id = requestAnimationFrame(() => setMounted(true));
    return () => cancelAnimationFrame(id);
  }, []);


  return (
    <Box sx={{ minHeight: '100vh', backgroundColor: '#FFFFFF' }}>
      <ConsoleBar />

      {/* nav */}
      <Box
        sx={{
          height: 58, display: 'flex', alignItems: 'center', px: { xs: 2.5, md: 5 }, gap: 1.5,
          borderBottom: '1px solid #ECEEF1',
          backgroundColor: '#FFFFFF', 
          position: 'sticky', top: 0, zIndex: 30,
        }}
      >
        <ShieldOutlinedIcon sx={{ color: '#076E7C', fontSize: 23 }} />
        <Typography sx={{ fontWeight: 800, letterSpacing: 2.4, fontSize: 15 }}>NETFORENSIQ</Typography>
        <Box sx={{ width: '1px', height: 20, backgroundColor: '#E2E5E9', mx: 1, display: { xs: 'none', sm: 'block' } }} />
        <Typography sx={{ fontSize: 13, color: '#5A6068', display: { xs: 'none', sm: 'block' } }}>
          Network &amp; Packet Forensics Platform
        </Typography>
        <Box sx={{ flexGrow: 1 }} />
        <Button
          component={RouterLink} to="/login" variant="outlined" size="small"
          startIcon={<LoginIcon sx={{ fontSize: 16 }} />}
          sx={{
            borderColor: 'rgba(7,110,124,0.38)', color: '#076E7C',
            fontSize: 12.5, fontWeight: 600, borderRadius: 1.5, px: 2,
            '&:hover': { borderColor: '#076E7C', backgroundColor: 'rgba(7,110,124,0.09)' },
          }}
        >
          Sign In
        </Button>
      </Box>

      {/* hero */}
      <Box
        sx={{
          position: 'relative', overflow: 'hidden',
          borderBottom: '1px solid #ECEEF1',
          // Something for the glass to refract.
          //
          // Two very low washes in the palette's own blues, over the ruling of
          // a ledger page. It is the texture of security print — the reason a
          // stamp paper looks like a stamp paper — and unlike an animated
          // shader it costs nothing, survives being projected in a lit room,
          // and is still there when the page is printed to a case file.
          backgroundColor: '#FFFFFF',
          backgroundImage: `
            radial-gradient(1100px 480px at 80% -12%, rgba(7,110,124,0.07), transparent 62%),
            radial-gradient(880px 420px at 10% 108%, rgba(31,58,95,0.055), transparent 62%),
            linear-gradient(rgba(17,19,21,0.028) 1px, transparent 1px),
            linear-gradient(90deg, rgba(17,19,21,0.028) 1px, transparent 1px)
          `,
          backgroundSize: '100% 100%, 100% 100%, 30px 30px, 30px 30px',
        }}
      >

        <Box
          sx={{
            position: 'relative', zIndex: 1, display: 'flex',
            flexDirection: { xs: 'column', md: 'row' }, gap: 5,
            maxWidth: 1180, mx: 'auto', px: { xs: 3, md: 5 }, py: { xs: 6, md: 9 },
            alignItems: 'center',
          }}
        >
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Box
              sx={{
                display: 'inline-flex', alignItems: 'center', gap: 1, mb: 2.5,
                px: 1.6, py: 0.6, borderRadius: 10,
                border: '1px solid #E2E5E9',
                backgroundColor: '#F4F5F7',
                opacity: mounted ? 1 : 0, transform: mounted ? 'none' : 'translateY(10px)',
                transition: 'all 0.6s ease',
              }}
            >
              <Box sx={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: '#1B6E3C', boxShadow: '0 0 8px #1B6E3C' }} />
              <Typography
                sx={{
                  fontSize: 10.5, letterSpacing: 0.9,
                  fontFamily: "'JetBrains Mono', monospace", color: '#5A6068',
                }}
              >
                BUILT FOR CYBER CRIME INVESTIGATION · KANAD S.H.I.E.L.D. 2026
              </Typography>
            </Box>

            <Typography
              sx={{
                fontSize: { xs: '2.1rem', md: '3.1rem' }, fontWeight: 800,
                lineHeight: 1.13, letterSpacing: -1, mb: 2,
                opacity: mounted ? 1 : 0, transform: mounted ? 'none' : 'translateY(16px)',
                transition: 'all 0.7s ease 0.1s',
              }}
            >
              Detect the intrusion.
              <br />
              <Box
                component="span"
                sx={{
                  color: '#111315', borderBottom: '3px solid #111315',
                }}
              >
                Prove it in court.
              </Box>
            </Typography>

            <Typography
              sx={{
                fontSize: 14.5, lineHeight: 1.75, color: '#5A6068',
                maxWidth: 520, mb: 3.5,
                opacity: mounted ? 1 : 0, transform: mounted ? 'none' : 'translateY(16px)',
                transition: 'all 0.7s ease 0.2s',
              }}
            >
              Packet analysis with every finding traced to a cited threshold, and a
              hash-chained custody record behind it — engineered for investigations
              that must survive legal scrutiny, not just detect a threat.
            </Typography>

            <Box
              sx={{
                display: 'flex', gap: 1.6, flexWrap: 'wrap',
                opacity: mounted ? 1 : 0, transform: mounted ? 'none' : 'translateY(16px)',
                transition: 'all 0.7s ease 0.3s',
              }}
            >
              <Button
                component={RouterLink} to="/login" variant="contained"
                startIcon={<LoginIcon sx={{ fontSize: 17 }} />}
                sx={{
                  px: 3, py: 1.15, fontWeight: 700, fontSize: 13, letterSpacing: 0.8,
                  borderRadius: 1.5, backgroundColor: '#111315', color: '#FFFFFF',
                  transition: 'all 0.25s cubic-bezier(0.4,0,0.2,1)',
                  '&:hover': {
                    backgroundColor: '#2B3138', boxShadow: '0 0 34px rgba(0,212,255,0.55)',
                  },
                }}
              >
                ACCESS TERMINAL
              </Button>
              <Button
                component={RouterLink} to="/register" variant="outlined"
                startIcon={<PersonAddAltIcon sx={{ fontSize: 17 }} />}
                sx={{
                  px: 3, py: 1.15, fontWeight: 700, fontSize: 13, letterSpacing: 0.8,
                  borderRadius: 1.5, borderColor: '#C7CCD2',
                  color: '#2B3138',
                  transition: 'all 0.25s',
                  '&:hover': {
                    borderColor: 'rgba(7,110,124,0.5)', backgroundColor: 'rgba(7,110,124,0.07)',
                    color: '#076E7C', transform: 'translateY(-2px)',
                  },
                }}
              >
                REQUEST ENROLLMENT
              </Button>
            </Box>
          </Box>

          {/* live telemetry preview panel */}
          <Box
            sx={{
              width: { xs: '100%', md: 320 }, flexShrink: 0, p: 2.5,
              borderRadius: 2,
              // Frosted, not flat.
              //
              // Glassmorphism used everywhere is the signature of a template.
              // Used once, on the one panel that explains what the product
              // does, it is a technique: the panel sits visibly *above* the
              // ruled ground instead of being pasted onto it, which is the
              // whole reason to spend depth on something.
              //
              // Three shadows, doing three jobs: an inset highlight for the
              // lit top edge, a long soft cast for elevation, and a short tight
              // one for contact. A single shadow reads as a sticker.
              position: 'relative',
              backgroundColor: 'rgba(255,255,255,0.62)',
              backdropFilter: 'blur(18px) saturate(1.2)',
              WebkitBackdropFilter: 'blur(18px) saturate(1.2)',
              border: '1px solid rgba(255,255,255,0.9)',
              outline: '1px solid rgba(17,19,21,0.06)',
              outlineOffset: '-1px',
              boxShadow: `
                0 1px 0 rgba(255,255,255,0.95) inset,
                0 24px 48px -28px rgba(17,19,21,0.32),
                0 3px 8px -4px rgba(17,19,21,0.10)
              `,
              opacity: mounted ? 1 : 0,
              transform: mounted ? 'none' : 'translateY(24px)',
              transition: 'all 0.8s ease 0.35s',
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <Typography
                sx={{
                  fontSize: 10, letterSpacing: 1.5, flexGrow: 1,
                  fontFamily: "'JetBrains Mono', monospace", color: '#5A6068',
                }}
              >
                HOW A CAPTURE BECOMES EVIDENCE
              </Typography>
            </Box>

            {/*
              This panel previously showed "Packets / sec 84.2 K", "Evidence
              sealed 2,417" and a pulsing REC indicator over Math.sin
              sparklines — none of it real, and nothing in the product records
              anything live. It is pre-authentication, so no API can back it
              either. It now describes the pipeline instead of pretending to
              measure it.
            */}
            {[
              ['01', 'Seal', 'The capture is hashed with SHA-256 before any analysis reads it.'],
              ['02', 'Analyse', `Flows are reconstructed and ${spellOut(engine?.rule_count)} rules run over them, each stating its threshold and where it came from.`],
              ['03', 'Triage', 'An officer confirms, dismisses or escalates each finding.'],
              ['04', 'Certify', 'A Section 63 certificate is issued with the hash report enclosed.'],
            ].map(([step, title, body], i) => (
              <Box
                key={step}
                sx={{
                  display: 'flex', gap: 1.6, mb: 1.8,
                  opacity: mounted ? 1 : 0,
                  transform: mounted ? 'none' : 'translateX(10px)',
                  transition: `all 0.6s ease ${0.45 + i * 0.07}s`,
                }}
              >
                <Typography
                  sx={{
                    fontSize: 11, fontWeight: 700, minWidth: 20,
                    fontFamily: "'JetBrains Mono', monospace", color: '#076E7C',
                  }}
                >
                  {step}
                </Typography>
                <Box>
                  <Typography sx={{ fontSize: 13, fontWeight: 600, color: '#111315' }}>
                    {title}
                  </Typography>
                  <Typography sx={{ fontSize: 12, lineHeight: 1.6, color: '#5A6068' }}>
                    {body}
                  </Typography>
                </Box>
              </Box>
            ))}

            <Box sx={{ height: '1px', backgroundColor: '#E2E5E9', my: 1.8 }} />

            <Typography
              sx={{
                fontSize: 11, lineHeight: 1.6, color: '#5A6068',
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              No figures are shown here because none would be real until a
              capture is loaded. Sign in to see live ones.
            </Typography>
          </Box>
        </Box>
      </Box>

      {/* capability panels */}
      <Box sx={{ maxWidth: 1180, mx: 'auto', px: { xs: 3, md: 5 }, py: { xs: 6, md: 8 } }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.6, mb: 3.5 }}>
          <Typography
            sx={{
              fontSize: 10.5, letterSpacing: 1.6, whiteSpace: 'nowrap',
              fontFamily: "'JetBrains Mono', monospace", color: '#076E7C',
            }}
          >
            PLATFORM CAPABILITIES
          </Typography>
          <Box sx={{ flexGrow: 1, height: '1px', backgroundColor: '#E2E5E9' }} />
        </Box>

        <Box
          sx={{
            display: 'grid',
            gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr', lg: 'repeat(4,1fr)' },
            gap: 2.2,
          }}
        >
          {features.map((f, i) => (
            <Box
              key={f.title}
              sx={{
                p: 2.5, borderRadius: 2, position: 'relative', overflow: 'hidden',
                backgroundColor: '#F4F5F7',
                border: '1px solid #E2E5E9',
                transition: 'all 0.3s cubic-bezier(0.4,0,0.2,1)',
                animation: `panelRise 0.55s ease ${0.1 + i * 0.08}s both`,
                '@keyframes panelRise': {
                  from: { opacity: 0, transform: 'translateY(18px)' },
                  to: { opacity: 1, transform: 'translateY(0)' },
                },
                '&::after': {
                  content: '""', position: 'absolute', top: 0, left: 0, right: 0, height: '1px',
                  backgroundColor: f.color,
                  opacity: 0, transition: 'opacity 0.3s',
                },
                '&:hover': {
                  borderColor: `${f.color}44`,
                  backgroundColor: '#F4F5F7',
                },
                '&:hover::after': { opacity: 1 },
              }}
            >
              <Box
                sx={{
                  width: 40, height: 40, borderRadius: 1.5, mb: 1.8,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  backgroundColor: `${f.color}14`,
                  border: `1px solid ${f.color}33`,
                  color: f.color,
                  '& svg': { fontSize: 20 },
                }}
              >
                {f.icon}
              </Box>
              <Typography
                sx={{
                  fontSize: 9.5, letterSpacing: 1.2, mb: 0.7,
                  fontFamily: "'JetBrains Mono', monospace", color: f.color,
                }}
              >
                {f.tag}
              </Typography>
              <Typography sx={{ fontSize: 14.5, fontWeight: 700, mb: 1 }}>{f.title}</Typography>
              <Typography sx={{ fontSize: 12.5, lineHeight: 1.65, color: '#5A6068' }}>
                {typeof f.desc === 'function' ? f.desc(engine) : f.desc}
              </Typography>
            </Box>
          ))}
        </Box>
      </Box>

      {/* footer strip */}
      <Box
        sx={{
          borderTop: '1px solid #ECEEF1',
          px: { xs: 3, md: 5 }, py: 2.5,
          display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap',
        }}
      >
        <Typography
          sx={{
            fontSize: 10.5, letterSpacing: 0.8,
            fontFamily: "'JetBrains Mono', monospace", color: '#5A6068',
          }}
        >
          NETFORENSIQ v{engine?.version ?? '—'}
        </Typography>
        <Box sx={{ flexGrow: 1 }} />
        <Typography
          sx={{
            fontSize: 10.5, letterSpacing: 0.8,
            fontFamily: "'JetBrains Mono', monospace", color: '#5A6068',
          }}
        >
          Sign-in attempts are recorded
        </Typography>
      </Box>
    </Box>
  );
}

export default LandingPage;