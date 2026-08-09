import { useEffect, useRef, useState } from 'react';
import { Box, Typography, Button } from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import ShieldOutlinedIcon from '@mui/icons-material/ShieldOutlined';
import LoginIcon from '@mui/icons-material/Login';
import PersonAddAltIcon from '@mui/icons-material/PersonAddAlt';
import RadarIcon from '@mui/icons-material/Radar';
import HubIcon from '@mui/icons-material/Hub';
import GavelIcon from '@mui/icons-material/Gavel';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import { ConsoleBar, MiniSpark } from './LoginPage';

const spark = (s) =>
  Array.from({ length: 20 }, (_, i) => 18 + Math.abs(Math.sin(i * s) * 48) + (i % 3) * 6);

const features = [
  { icon: <RadarIcon />, title: 'AI Anomaly Detection', tag: 'ISOLATION FOREST',
    desc: 'Unsupervised behavioural modelling flags exfiltration, covert tunnels and insider activity without prior signatures.', color: '#00D4FF' },
  { icon: <HubIcon />, title: 'Flow Visualization', tag: 'D3 GRAPH ENGINE',
    desc: 'Source-to-destination mapping with suspicious node highlighting and timeline-correlated attack progression.', color: '#00E68A' },
  { icon: <GavelIcon />, title: 'Forensic Workflow', tag: 'CASE MANAGEMENT',
    desc: 'Session reconstruction, historical search and investigator case files built around real procedural workflow.', color: '#FFB020' },
  { icon: <VerifiedUserIcon />, title: 'Sealed Evidence', tag: 'SHA-256 CUSTODY',
    desc: 'Every artefact hashed at capture with immutable chain-of-custody records and court-ready report generation.', color: '#A855F7' },
];

function LandingPage() {
  const canvasRef = useRef(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => { setMounted(true); }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    let animationId;
    const particles = [];

    const resize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
    };
    resize();
    window.addEventListener('resize', resize);

    for (let i = 0; i < 60; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.32,
        vy: (Math.random() - 0.5) * 0.32,
      });
    }

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      for (const p of particles) {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
        if (p.y < 0 || p.y > canvas.height) p.vy *= -1;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 1.5, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(0,212,255,0.5)';
        ctx.fill();
      }
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const d = Math.sqrt(dx * dx + dy * dy);
          if (d < 130) {
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.strokeStyle = `rgba(0,212,255,${0.12 * (1 - d / 130)})`;
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        }
      }
      animationId = requestAnimationFrame(draw);
    };
    draw();

    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return (
    <Box sx={{ minHeight: '100vh', backgroundColor: '#080B14' }}>
      <ConsoleBar />

      {/* nav */}
      <Box
        sx={{
          height: 58, display: 'flex', alignItems: 'center', px: { xs: 2.5, md: 5 }, gap: 1.5,
          borderBottom: '1px solid rgba(255,255,255,0.05)',
          backgroundColor: 'rgba(11,15,26,0.75)', backdropFilter: 'blur(14px)',
          position: 'sticky', top: 0, zIndex: 30,
        }}
      >
        <ShieldOutlinedIcon sx={{ color: '#00D4FF', fontSize: 23 }} />
        <Typography sx={{ fontWeight: 800, letterSpacing: 2.4, fontSize: 15 }}>NETFORENSIQ</Typography>
        <Box sx={{ width: '1px', height: 20, backgroundColor: 'rgba(255,255,255,0.1)', mx: 1, display: { xs: 'none', sm: 'block' } }} />
        <Typography sx={{ fontSize: 13, color: 'rgba(229,231,235,0.55)', display: { xs: 'none', sm: 'block' } }}>
          Network &amp; Packet Forensics Platform
        </Typography>
        <Box sx={{ flexGrow: 1 }} />
        <Button
          component={RouterLink} to="/login" variant="outlined" size="small"
          startIcon={<LoginIcon sx={{ fontSize: 16 }} />}
          sx={{
            borderColor: 'rgba(0,212,255,0.32)', color: '#00D4FF',
            fontSize: 12.5, fontWeight: 600, borderRadius: 1.5, px: 2,
            '&:hover': { borderColor: '#00D4FF', backgroundColor: 'rgba(0,212,255,0.07)' },
          }}
        >
          Sign In
        </Button>
      </Box>

      {/* hero */}
      <Box
        sx={{
          position: 'relative', overflow: 'hidden',
          borderBottom: '1px solid rgba(255,255,255,0.05)',
        }}
      >
        <Box
          component="canvas" ref={canvasRef}
          sx={{ position: 'absolute', inset: 0, width: '100%', height: '100%', zIndex: 0 }}
        />
        <Box
          sx={{
            position: 'absolute', width: 900, height: 620, borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(0,212,255,0.09) 0%, transparent 65%)',
            top: '-30%', left: '50%', transform: 'translateX(-50%)', pointerEvents: 'none', zIndex: 0,
          }}
        />

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
                border: '1px solid rgba(0,212,255,0.25)',
                backgroundColor: 'rgba(0,212,255,0.05)',
                opacity: mounted ? 1 : 0, transform: mounted ? 'none' : 'translateY(10px)',
                transition: 'all 0.6s ease',
              }}
            >
              <Box sx={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: '#00E68A', boxShadow: '0 0 8px #00E68A' }} />
              <Typography
                sx={{
                  fontSize: 10.5, letterSpacing: 0.9,
                  fontFamily: "'JetBrains Mono', monospace", color: 'rgba(229,231,235,0.6)',
                }}
              >
                CYBER CRIME BRANCH · AUTHORIZED DEPLOYMENT
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
                  background: 'linear-gradient(92deg,#00D4FF 0%,#A855F7 100%)',
                  WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
                }}
              >
                Prove it in court.
              </Box>
            </Typography>

            <Typography
              sx={{
                fontSize: 14.5, lineHeight: 1.75, color: 'rgba(229,231,235,0.6)',
                maxWidth: 520, mb: 3.5,
                opacity: mounted ? 1 : 0, transform: mounted ? 'none' : 'translateY(16px)',
                transition: 'all 0.7s ease 0.2s',
              }}
            >
              Real-time packet capture, AI-driven anomaly detection and tamper-proof
              evidence generation — engineered for investigations that must survive
              legal scrutiny, not just detect a threat.
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
                  borderRadius: 1.5, backgroundColor: '#00D4FF', color: '#061018',
                  boxShadow: '0 0 22px rgba(0,212,255,0.32)',
                  transition: 'all 0.25s cubic-bezier(0.4,0,0.2,1)',
                  '&:hover': {
                    backgroundColor: '#25DDFF', boxShadow: '0 0 34px rgba(0,212,255,0.55)',
                    transform: 'translateY(-2px)',
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
                  borderRadius: 1.5, borderColor: 'rgba(255,255,255,0.14)',
                  color: 'rgba(229,231,235,0.85)',
                  transition: 'all 0.25s',
                  '&:hover': {
                    borderColor: 'rgba(0,212,255,0.5)', backgroundColor: 'rgba(0,212,255,0.05)',
                    color: '#00D4FF', transform: 'translateY(-2px)',
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
              borderRadius: 2, backgroundColor: 'rgba(255,255,255,0.025)',
              border: '1px solid rgba(255,255,255,0.07)',
              boxShadow: '0 20px 60px -20px rgba(0,0,0,0.7)',
              opacity: mounted ? 1 : 0, transform: mounted ? 'none' : 'translateY(24px)',
              transition: 'all 0.8s ease 0.35s',
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <Typography
                sx={{
                  fontSize: 10, letterSpacing: 1.5, flexGrow: 1,
                  fontFamily: "'JetBrains Mono', monospace", color: 'rgba(229,231,235,0.35)',
                }}
              >
                LIVE CAPTURE PREVIEW
              </Typography>
              <Box
                sx={{
                  width: 6, height: 6, borderRadius: '50%', backgroundColor: '#FF3B5C',
                  boxShadow: '0 0 8px #FF3B5C',
                  animation: 'blip 1.6s ease-in-out infinite',
                  '@keyframes blip': { '0%,100%': { opacity: 1 }, '50%': { opacity: 0.25 } },
                }}
              />
              <Typography
                sx={{
                  fontSize: 9.5, ml: 0.7, letterSpacing: 0.8,
                  fontFamily: "'JetBrains Mono', monospace", color: '#FF3B5C',
                }}
              >
                REC
              </Typography>
            </Box>

            <MiniSpark label="Packets / sec" value="84.2 K" delta="6%" color="#00D4FF" data={spark(0.5)} delay={0.5} />
            <MiniSpark label="Flows analysed" value="512.0 M" delta="7%" color="#00E68A" data={spark(0.8)} delay={0.57} />
            <MiniSpark label="Anomalies open" value="1,482" delta="3%" color="#FFB020" data={spark(1.1)} delay={0.64} up={false} />
            <MiniSpark label="Evidence sealed" value="2,417" delta="9%" color="#A855F7" data={spark(1.4)} delay={0.71} />

            <Box sx={{ height: '1px', backgroundColor: 'rgba(255,255,255,0.06)', my: 1.8 }} />

            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
              {[['UPTIME', '2d 04h'], ['NODES', '03'], ['INTEGRITY', '100%']].map(([k, v]) => (
                <Box key={k}>
                  <Typography
                    sx={{
                      fontSize: 9, letterSpacing: 1,
                      fontFamily: "'JetBrains Mono', monospace", color: 'rgba(229,231,235,0.3)',
                    }}
                  >
                    {k}
                  </Typography>
                  <Typography
                    sx={{
                      fontSize: 13, fontWeight: 600,
                      fontFamily: "'JetBrains Mono', monospace", color: '#E5E7EB',
                    }}
                  >
                    {v}
                  </Typography>
                </Box>
              ))}
            </Box>
          </Box>
        </Box>
      </Box>

      {/* capability panels */}
      <Box sx={{ maxWidth: 1180, mx: 'auto', px: { xs: 3, md: 5 }, py: { xs: 6, md: 8 } }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.6, mb: 3.5 }}>
          <Typography
            sx={{
              fontSize: 10.5, letterSpacing: 1.6, whiteSpace: 'nowrap',
              fontFamily: "'JetBrains Mono', monospace", color: '#00D4FF',
            }}
          >
            PLATFORM CAPABILITIES
          </Typography>
          <Box sx={{ flexGrow: 1, height: '1px', background: 'linear-gradient(90deg, rgba(0,212,255,0.28), transparent)' }} />
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
                backgroundColor: 'rgba(255,255,255,0.022)',
                border: '1px solid rgba(255,255,255,0.06)',
                transition: 'all 0.3s cubic-bezier(0.4,0,0.2,1)',
                animation: `panelRise 0.55s ease ${0.1 + i * 0.08}s both`,
                '@keyframes panelRise': {
                  from: { opacity: 0, transform: 'translateY(18px)' },
                  to: { opacity: 1, transform: 'translateY(0)' },
                },
                '&::after': {
                  content: '""', position: 'absolute', top: 0, left: 0, right: 0, height: '1px',
                  background: `linear-gradient(90deg, transparent, ${f.color}, transparent)`,
                  opacity: 0, transition: 'opacity 0.3s',
                },
                '&:hover': {
                  borderColor: `${f.color}44`,
                  backgroundColor: 'rgba(255,255,255,0.038)',
                  transform: 'translateY(-4px)',
                  boxShadow: `0 14px 34px -14px ${f.color}55`,
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
              <Typography sx={{ fontSize: 12.5, lineHeight: 1.65, color: 'rgba(229,231,235,0.52)' }}>
                {f.desc}
              </Typography>
            </Box>
          ))}
        </Box>
      </Box>

      {/* footer strip */}
      <Box
        sx={{
          borderTop: '1px solid rgba(255,255,255,0.05)',
          px: { xs: 3, md: 5 }, py: 2.5,
          display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap',
        }}
      >
        <Typography
          sx={{
            fontSize: 10.5, letterSpacing: 0.8,
            fontFamily: "'JetBrains Mono', monospace", color: 'rgba(229,231,235,0.3)',
          }}
        >
          NETFORENSIQ v1.0 · RESTRICTED DEPLOYMENT
        </Typography>
        <Box sx={{ flexGrow: 1 }} />
        <Typography
          sx={{
            fontSize: 10.5, letterSpacing: 0.8,
            fontFamily: "'JetBrains Mono', monospace", color: 'rgba(229,231,235,0.3)',
          }}
        >
          ALL ACCESS LOGGED &amp; AUDITED
        </Typography>
      </Box>
    </Box>
  );
}

export default LandingPage;