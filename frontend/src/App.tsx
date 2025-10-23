import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import { 
  AppBar, 
  Toolbar, 
  Typography, 
  Drawer, 
  List, 
  ListItem, 
  ListItemText, 
  ListItemIcon,
  CssBaseline, 
  Box,
  IconButton,
  Divider,
  Chip,
  ThemeProvider,
  createTheme,
  Tooltip
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Security as SecurityIcon,
  TrendingUp as TrendingUpIcon,
  Search as SearchIcon,
  BugReport as BugReportIcon,
  Code as CodeIcon,
  Brightness4,
  Brightness7
} from '@mui/icons-material';
import Dashboard from './components/dashboard';
import AccessControl from './components/access-control';
import ThreatPrediction from './components/threat-prediction';
import ThreatHunting from './components/threat-hunting';
import IncidentResponse from './components/incident-response';

// Custom theme using Reputationsquad Veille palette
const createAppTheme = (mode: 'light' | 'dark') => createTheme({
  palette: {
    mode,
    primary: {
      main: '#86C232',
      light: '#9BCF4A',
      dark: '#61892F',
    },
    secondary: {
      main: '#61892F',
      light: '#7A9F3A',
      dark: '#4A6B24',
    },
    background: {
      default: mode === 'dark' ? '#222629' : '#f8f9fa',
      paper: mode === 'dark' ? '#474B4F' : '#ffffff',
    },
    text: {
      primary: mode === 'dark' ? '#86C232' : '#2c3e50',
      secondary: mode === 'dark' ? '#ffffff' : '#34495e',
    },
    error: {
      main: '#ef4444',
    },
    warning: {
      main: '#f59e0b',
    },
    success: {
      main: '#86C232',
    },
    info: {
      main: '#61892F',
    },
  },
  typography: {
    fontFamily: 'Google Sans Code, Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    h1: {
      fontWeight: 700,
      letterSpacing: '-0.025em',
    },
    h2: {
      fontWeight: 600,
      letterSpacing: '-0.025em',
    },
    h3: {
      fontWeight: 600,
      letterSpacing: '-0.025em',
    },
    h4: {
      fontWeight: 600,
      letterSpacing: '-0.025em',
    },
    h5: {
      fontWeight: 600,
      letterSpacing: '-0.025em',
    },
    h6: {
      fontWeight: 600,
      letterSpacing: '-0.025em',
    },
    body1: {
      lineHeight: 1.6,
    },
    body2: {
      lineHeight: 1.6,
    },
  },
  shape: {
    borderRadius: 12,
  },
  components: {
    MuiCard: {
      styleOverrides: {
        root: {
          background: mode === 'dark' ? '#474B4F' : '#ffffff',
          backdropFilter: 'blur(10px)',
          border: mode === 'dark' ? '1px solid rgba(134, 194, 50, 0.1)' : '1px solid rgba(134, 194, 50, 0.2)',
          boxShadow: mode === 'dark' ? '0 4px 20px rgba(0, 0, 0, 0.3)' : '0 4px 20px rgba(0, 0, 0, 0.1)',
          transition: 'all 0.3s ease',
          '&:hover': {
            transform: 'translateY(-4px)',
            boxShadow: mode === 'dark' ? '0 12px 40px rgba(0, 0, 0, 0.4)' : '0 12px 40px rgba(0, 0, 0, 0.15)',
            borderColor: mode === 'dark' ? 'rgba(134, 194, 50, 0.3)' : 'rgba(134, 194, 50, 0.4)',
          },
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          background: mode === 'dark' ? '#474B4F' : '#ffffff',
          backdropFilter: 'blur(10px)',
          border: mode === 'dark' ? '1px solid rgba(134, 194, 50, 0.1)' : '1px solid rgba(134, 194, 50, 0.2)',
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 500,
          borderRadius: 8,
          fontFamily: 'Google Sans Code, sans-serif',
          transition: 'all 0.3s ease',
          position: 'relative',
          overflow: 'hidden',
          '&::before': {
            content: '""',
            position: 'absolute',
            top: 0,
            left: '-100%',
            width: '100%',
            height: '100%',
            background: 'linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent)',
            transition: 'left 0.5s',
          },
          '&:hover::before': {
            left: '100%',
          },
        },
        contained: {
          background: 'linear-gradient(135deg, #86C232 0%, #61892F 100%)',
          '&:hover': {
            background: 'linear-gradient(135deg, #61892F 0%, #86C232 100%)',
            transform: 'translateY(-2px)',
            boxShadow: '0 8px 25px rgba(134, 194, 50, 0.4)',
          },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          fontFamily: 'Google Sans Code, sans-serif',
          fontWeight: 500,
          transition: 'all 0.3s ease',
          '&:hover': {
            transform: 'translateY(-1px)',
          },
        },
      },
    },
    MuiTextField: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            background: 'rgba(71, 75, 79, 0.8)',
            border: '1px solid rgba(134, 194, 50, 0.2)',
            '&:hover': {
              border: '1px solid rgba(134, 194, 50, 0.4)',
            },
            '&.Mui-focused': {
              border: '1px solid #86C232',
            },
          },
        },
      },
    },
    MuiIconButton: {
      styleOverrides: {
        root: {
          transition: 'all 0.3s ease',
          '&:hover': {
            transform: 'scale(1.1)',
          },
        },
      },
    },
  },
});

const drawerWidth = 280;

const navItems = [
  { 
    text: 'Dashboard', 
    path: '/', 
    icon: <DashboardIcon />,
    description: 'System Overview'
  },
  { 
    text: 'Access Control', 
    path: '/access-control', 
    icon: <SecurityIcon />,
    description: 'User Authentication'
  },
  { 
    text: 'Threat Prediction', 
    path: '/threat-prediction', 
    icon: <TrendingUpIcon />,
    description: 'ML Predictions'
  },
  { 
    text: 'Threat Hunting', 
    path: '/threat-hunting', 
    icon: <SearchIcon />,
    description: 'Active Investigation'
  },
  { 
    text: 'Incident Response', 
    path: '/incident-response', 
    icon: <BugReportIcon />,
    description: 'Security Incidents'
  },
];

const NavigationItem = ({ item, isActive, mode }: { item: any; isActive: boolean; mode: 'light' | 'dark' }) => (
  <ListItem 
    button 
    component={Link} 
    to={item.path}
    sx={{
      margin: '8px 16px',
      borderRadius: '12px',
      backgroundColor: isActive ? 'rgba(134, 194, 50, 0.15)' : 'transparent',
      border: isActive ? '1px solid rgba(134, 194, 50, 0.3)' : '1px solid transparent',
      '&:hover': {
        backgroundColor: isActive ? 'rgba(134, 194, 50, 0.2)' : mode === 'dark' ? 'rgba(71, 75, 79, 0.3)' : 'rgba(134, 194, 50, 0.1)',
        transform: 'translateX(4px)',
      },
      transition: 'all 0.3s ease',
      animation: isActive ? 'slideInLeft 0.6s ease-out' : 'none',
    }}
  >
    <ListItemIcon sx={{ 
      color: isActive ? '#86C232' : mode === 'dark' ? '#ffffff' : '#2c3e50',
      minWidth: '40px',
      transition: 'all 0.3s ease',
    }}>
      {item.icon}
    </ListItemIcon>
    <Box sx={{ flex: 1 }}>
      <ListItemText 
        primary={item.text}
        secondary={item.description}
        primaryTypographyProps={{
          fontSize: '14px',
          fontWeight: isActive ? 600 : 500,
          color: isActive ? '#86C232' : mode === 'dark' ? '#ffffff' : '#2c3e50',
          fontFamily: 'Google Sans Code, sans-serif',
        }}
        secondaryTypographyProps={{
          fontSize: '12px',
          color: isActive ? '#61892F' : mode === 'dark' ? '#474B4F' : '#34495e',
          fontFamily: 'Google Sans Code, sans-serif',
        }}
      />
    </Box>
  </ListItem>
);

const Navigation = ({ mode }: { mode: 'light' | 'dark' }) => {
  const location = useLocation();
  
  return (
    <Box sx={{ 
      height: '100%',
      background: mode === 'dark' 
        ? 'linear-gradient(180deg, rgba(134, 194, 50, 0.02) 0%, rgba(34, 38, 41, 0.01) 100%)'
        : 'linear-gradient(180deg, rgba(134, 194, 50, 0.05) 0%, rgba(248, 249, 250, 0.01) 100%)',
      borderRight: mode === 'dark' ? '1px solid rgba(134, 194, 50, 0.1)' : '1px solid rgba(134, 194, 50, 0.2)',
      animation: 'fadeInUp 0.8s ease-out',
    }}>
      <Box sx={{ p: 3, borderBottom: mode === 'dark' ? '1px solid rgba(134, 194, 50, 0.1)' : '1px solid rgba(134, 194, 50, 0.2)' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
          <CodeIcon sx={{ color: '#86C232', fontSize: 28, animation: 'pulse 2s infinite' }} />
          <Typography 
            variant="h6" 
            sx={{ 
              fontWeight: 700,
              background: 'linear-gradient(135deg, #86C232 0%, #61892F 100%)',
              backgroundClip: 'text',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              fontFamily: 'Google Sans Code, sans-serif',
            }}
          >
            AISF Platform
          </Typography>
        </Box>
        <Chip 
          label="Security Intelligence" 
          size="small"
          sx={{
            background: 'rgba(134, 194, 50, 0.1)',
            color: '#86C232',
            border: '1px solid rgba(134, 194, 50, 0.3)',
            fontFamily: 'Google Sans Code, sans-serif',
            fontWeight: 500,
          }}
        />
      </Box>
      
      <Box sx={{ p: 2 }}>
        <Typography 
          variant="overline" 
          sx={{ 
            color: mode === 'dark' ? '#ffffff' : '#2c3e50',
            fontSize: '11px',
            fontWeight: 600,
            letterSpacing: '0.1em',
            textTransform: 'uppercase',
            mb: 2,
            display: 'block',
            fontFamily: 'Google Sans Code, sans-serif',
          }}
        >
          Navigation
        </Typography>
        <List sx={{ p: 0 }}>
          {navItems.map((item, index) => (
            <NavigationItem 
              key={item.text} 
              item={item} 
              isActive={location.pathname === item.path}
              mode={mode}
            />
          ))}
        </List>
      </Box>
      
      <Box sx={{ 
        position: 'absolute', 
        bottom: 0, 
        left: 0, 
        right: 0, 
        p: 2,
        borderTop: mode === 'dark' ? '1px solid rgba(134, 194, 50, 0.1)' : '1px solid rgba(134, 194, 50, 0.2)',
        background: mode === 'dark' ? 'rgba(71, 75, 79, 0.1)' : 'rgba(134, 194, 50, 0.05)',
      }}>
        <Typography 
          variant="caption" 
          sx={{ 
            color: mode === 'dark' ? '#ffffff' : '#2c3e50',
            fontFamily: 'Google Sans Code, sans-serif',
            display: 'block',
            textAlign: 'center',
          }}
        >
          AI Security Framework v2.0
        </Typography>
      </Box>
    </Box>
  );
};

function App() {
  const [mode, setMode] = useState<'light' | 'dark'>('dark');
  const theme = createAppTheme(mode);

  const toggleColorMode = () => {
    setMode((prevMode) => (prevMode === 'light' ? 'dark' : 'light'));
  };

  return (
    <ThemeProvider theme={theme}>
    <Router>
        <Box sx={{ 
          display: 'flex', 
          minHeight: '100vh',
          background: mode === 'dark' ? '#222629' : '#f8f9fa',
          animation: 'fadeInUp 0.6s ease-out',
        }}>
        <CssBaseline />
          <AppBar 
            position="fixed" 
            sx={{ 
              zIndex: (theme) => theme.zIndex.drawer + 1,
              background: mode === 'dark' ? 'rgba(34, 38, 41, 0.9)' : 'rgba(255, 255, 255, 0.9)',
              backdropFilter: 'blur(20px)',
              borderBottom: mode === 'dark' ? '1px solid rgba(134, 194, 50, 0.1)' : '1px solid rgba(134, 194, 50, 0.2)',
              boxShadow: 'none',
              animation: 'slideInLeft 0.8s ease-out',
            }}
          >
            <Toolbar sx={{ justifyContent: 'space-between' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <Typography 
                  variant="h6" 
                  sx={{ 
                    fontWeight: 600,
                    color: '#86C232',
                    fontFamily: 'Google Sans Code, sans-serif',
                  }}
                >
              AISF Security Platform
            </Typography>
                <Chip 
                  label="Live" 
                  size="small"
                  sx={{
                    background: 'rgba(134, 194, 50, 0.2)',
                    color: '#86C232',
                    border: '1px solid rgba(134, 194, 50, 0.4)',
                    fontFamily: 'Google Sans Code, sans-serif',
                    fontWeight: 600,
                    fontSize: '10px',
                    animation: 'pulse 2s infinite',
                  }}
                />
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Chip 
                  label="Secure" 
                  size="small"
                  sx={{
                    background: 'rgba(97, 137, 47, 0.2)',
                    color: '#61892F',
                    border: '1px solid rgba(97, 137, 47, 0.4)',
                    fontFamily: 'Google Sans Code, sans-serif',
                    fontWeight: 500,
                  }}
                />
                <Tooltip title={`Switch to ${mode === 'dark' ? 'light' : 'dark'} mode`}>
                  <IconButton 
                    onClick={toggleColorMode}
                    sx={{ 
                      color: '#ffffff',
                      '&:hover': { 
                        color: '#86C232',
                        transform: 'rotate(180deg)',
                      },
                      transition: 'all 0.3s ease',
                    }}
                  >
                    {mode === 'dark' ? <Brightness7 /> : <Brightness4 />}
                  </IconButton>
                </Tooltip>
              </Box>
          </Toolbar>
        </AppBar>
        <Drawer
          variant="permanent"
          sx={{
            width: drawerWidth,
            flexShrink: 0,
              [`& .MuiDrawer-paper`]: { 
                width: drawerWidth, 
                boxSizing: 'border-box',
                background: 'transparent',
                border: 'none',
              },
          }}
        >
          <Toolbar />
            <Navigation mode={mode} />
        </Drawer>
          <Box 
            component="main" 
            sx={{ 
              flexGrow: 1,
              minHeight: '100vh',
              p: 4,
              background: mode === 'dark' ? '#222629' : '#f8f9fa',
              animation: 'fadeInUp 1s ease-out',
            }}
          >
          <Toolbar />
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/access-control" element={<AccessControl />} />
            <Route path="/threat-prediction" element={<ThreatPrediction />} />
            <Route path="/threat-hunting" element={<ThreatHunting />} />
            <Route path="/incident-response" element={<IncidentResponse />} />
          </Routes>
        </Box>
      </Box>
    </Router>
    </ThemeProvider>
  );
}

export default App;
