import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  LinearProgress,
  Chip,
  Alert,
  Button,
  CircularProgress,
  IconButton,
  Tooltip
} from '@mui/material';
import {
  Security,
  Warning,
  CheckCircle,
  TrendingUp,
  Refresh,
  Shield,
  BugReport,
  Timeline,
  Speed
} from '@mui/icons-material';
import { PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, LineChart, Line } from 'recharts';
import { apiService } from '../../services/api';

const COLORS = ['#86C232', '#61892F', '#474B4F', '#ffffff', '#222629', '#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4', '#feca57'];

const Dashboard: React.FC = () => {
  const [dashboardData, setDashboardData] = useState<any>(null);
  const [systemStatus, setSystemStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Fetch dashboard data
      const dashboard = await apiService.getDashboardData();
      console.log('Dashboard data received:', dashboard);
      console.log('Threat distribution data:', dashboard?.threat_distribution);
      setDashboardData(dashboard);
      
      // Fetch system status
      const status = await apiService.getSystemStatus();
      setSystemStatus(status);
      
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Error fetching dashboard data:', err);
      setError('Failed to load dashboard data. Please check if the backend server is running.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    
    // Refresh data every 30 seconds
    const interval = setInterval(fetchDashboardData, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleRefresh = () => {
    fetchDashboardData();
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress sx={{ color: '#86C232' }} />
      </Box>
    );
  }

  if (error) {
    return (
      <Box p={3}>
        <Alert 
          severity="error" 
          action={
            <Button color="inherit" size="small" onClick={handleRefresh}>
              Retry
            </Button>
          }
          sx={{
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: 2,
          }}
        >
          {error}
        </Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ animation: 'fadeInUp 0.8s ease-out' }}>
      {/* Header Section */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Box>
            <Typography 
              variant="h3" 
              sx={{ 
                fontWeight: 700,
                background: 'linear-gradient(135deg, #86C232 0%, #61892F 100%)',
                backgroundClip: 'text',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                mb: 1,
                fontFamily: 'Google Sans Code, sans-serif',
              }}
            >
              Security Intelligence Dashboard
            </Typography>
            <Typography 
              variant="body1" 
              sx={{ 
                color: '#ffffff',
                fontSize: '16px',
                fontWeight: 400,
                fontFamily: 'Google Sans Code, sans-serif',
              }}
            >
              Real-time monitoring and threat analysis
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Chip 
              label={`Updated ${lastUpdated.toLocaleTimeString()}`}
              variant="outlined"
              size="small"
              sx={{
                background: 'rgba(134, 194, 50, 0.1)',
                border: '1px solid rgba(134, 194, 50, 0.3)',
                color: '#86C232',
                fontFamily: 'Google Sans Code, sans-serif',
              }}
            />
            <Tooltip title="Refresh Data">
              <IconButton 
                onClick={handleRefresh}
                sx={{ 
                  color: '#ffffff',
                  '&:hover': { 
                    color: '#86C232',
                    transform: 'rotate(180deg)',
                  },
                  transition: 'all 0.3s ease',
                }}
              >
                <Refresh />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>
      </Box>

      {/* System Status Alert */}
      {systemStatus && (
        <Alert 
          severity={systemStatus.realtime_service?.is_running ? "success" : "warning"}
          sx={{ 
            mb: 3,
            background: systemStatus.realtime_service?.is_running ? 'rgba(134, 194, 50, 0.1)' : 'rgba(245, 158, 11, 0.1)',
            border: systemStatus.realtime_service?.is_running ? '1px solid rgba(134, 194, 50, 0.3)' : '1px solid rgba(245, 158, 11, 0.3)',
            borderRadius: 2,
            animation: 'slideInLeft 0.6s ease-out',
            color: '#86C232',
          }}
        >
          Real-time service: {systemStatus.realtime_service?.is_running ? "Running" : "Stopped"} | 
          Active connections: {systemStatus.realtime_service?.active_connections || 0} | 
          Update interval: {systemStatus.realtime_service?.update_interval || "N/A"}
        </Alert>
      )}

      {/* Security Metrics */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ 
            background: 'rgba(239, 68, 68, 0.05)',
            border: '1px solid rgba(239, 68, 68, 0.2)',
            '&:hover': {
              background: 'rgba(239, 68, 68, 0.08)',
              transform: 'translateY(-4px)',
            },
            transition: 'all 0.3s ease',
            animation: 'fadeInUp 0.8s ease-out',
          }}>
            <CardContent sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <Security sx={{ color: '#ef4444', fontSize: 32 }} />
                <Chip 
                  label="Threats" 
                  size="small"
                  sx={{
                    background: 'rgba(239, 68, 68, 0.2)',
                    color: '#ffffff',
                    fontWeight: 600,
                    fontFamily: 'Google Sans Code, sans-serif',
                  }}
                />
              </Box>
              <Typography variant="h4" sx={{ fontWeight: 700, color: '#86C232', mb: 1, fontFamily: 'Google Sans Code, sans-serif' }}>
                {dashboardData?.security_metrics?.total_threats || 0}
              </Typography>
              <Typography variant="body2" sx={{ color: '#ffffff', fontFamily: 'Google Sans Code, sans-serif' }}>
                Total Threats
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ 
            background: 'rgba(245, 158, 11, 0.05)',
            border: '1px solid rgba(245, 158, 11, 0.2)',
            '&:hover': {
              background: 'rgba(245, 158, 11, 0.08)',
              transform: 'translateY(-4px)',
            },
            transition: 'all 0.3s ease',
            animation: 'fadeInUp 0.9s ease-out',
          }}>
            <CardContent sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <Warning sx={{ color: '#f59e0b', fontSize: 32 }} />
                <Chip 
                  label="Active" 
                  size="small"
                  sx={{
                    background: 'rgba(245, 158, 11, 0.2)',
                    color: '#ffffff',
                    fontWeight: 600,
                    fontFamily: 'Google Sans Code, sans-serif',
                  }}
                />
              </Box>
              <Typography variant="h4" sx={{ fontWeight: 700, color: '#86C232', mb: 1, fontFamily: 'Google Sans Code, sans-serif' }}>
                {dashboardData?.security_metrics?.active_incidents || 0}
              </Typography>
              <Typography variant="body2" sx={{ color: '#ffffff', fontFamily: 'Google Sans Code, sans-serif' }}>
                Active Incidents
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ 
            background: 'rgba(134, 194, 50, 0.05)',
            border: '1px solid rgba(134, 194, 50, 0.2)',
            '&:hover': {
              background: 'rgba(134, 194, 50, 0.08)',
              transform: 'translateY(-4px)',
            },
            transition: 'all 0.3s ease',
            animation: 'fadeInUp 1.0s ease-out',
          }}>
            <CardContent sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <CheckCircle sx={{ color: '#86C232', fontSize: 32 }} />
                <Chip 
                  label="Blocked" 
                  size="small"
                  sx={{
                    background: 'rgba(134, 194, 50, 0.2)',
                    color: '#ffffff',
                    fontWeight: 600,
                    fontFamily: 'Google Sans Code, sans-serif',
                  }}
                />
              </Box>
              <Typography variant="h4" sx={{ fontWeight: 700, color: '#86C232', mb: 1, fontFamily: 'Google Sans Code, sans-serif' }}>
                {dashboardData?.security_metrics?.blocked_attacks || 0}
              </Typography>
              <Typography variant="body2" sx={{ color: '#ffffff', fontFamily: 'Google Sans Code, sans-serif' }}>
                Blocked Attacks
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ 
            background: 'rgba(97, 137, 47, 0.05)',
            border: '1px solid rgba(97, 137, 47, 0.2)',
            '&:hover': {
              background: 'rgba(97, 137, 47, 0.08)',
              transform: 'translateY(-4px)',
            },
            transition: 'all 0.3s ease',
            animation: 'fadeInUp 1.1s ease-out',
          }}>
            <CardContent sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <TrendingUp sx={{ color: '#61892F', fontSize: 32 }} />
                <Chip 
                  label="Health" 
                  size="small"
                  sx={{
                    background: 'rgba(97, 137, 47, 0.2)',
                    color: '#ffffff',
                    fontWeight: 600,
                    fontFamily: 'Google Sans Code, sans-serif',
                  }}
                />
              </Box>
              <Typography variant="h4" sx={{ fontWeight: 700, color: '#86C232', mb: 1, fontFamily: 'Google Sans Code, sans-serif' }}>
                {dashboardData?.security_metrics?.system_health || 0}%
              </Typography>
              <Typography variant="body2" sx={{ color: '#ffffff', fontFamily: 'Google Sans Code, sans-serif' }}>
                System Health
              </Typography>
              <LinearProgress 
                variant="determinate" 
                value={dashboardData?.security_metrics?.system_health || 0}
                sx={{ 
                  mt: 1,
                  height: 6,
                  borderRadius: 3,
                  backgroundColor: 'rgba(97, 137, 47, 0.2)',
                  '& .MuiLinearProgress-bar': {
                    backgroundColor: '#61892F',
                  }
                }}
              />
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3}>
        {/* Threat Trends */}
        <Grid item xs={12} md={8}>
          <Card sx={{ animation: 'slideInLeft 1.2s ease-out' }}>
            <CardContent sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 3, color: '#86C232', fontFamily: 'Google Sans Code, sans-serif' }}>
                Threat Trends (Last 7 Days)
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={dashboardData?.threat_trends || []}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(134, 194, 50, 0.1)" />
                  <XAxis dataKey="date" stroke="#ffffff" />
                  <YAxis stroke="#ffffff" />
                  <RechartsTooltip 
                    contentStyle={{
                      background: 'rgba(34, 38, 41, 0.9)',
                      border: '1px solid rgba(134, 194, 50, 0.3)',
                      borderRadius: 8,
                      color: '#86C232',
                    }}
                  />
                  <Line type="monotone" dataKey="threats" stroke="#86C232" name="Threats" strokeWidth={2} />
                  <Line type="monotone" dataKey="incidents" stroke="#61892F" name="Incidents" strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Threat Distribution */}
        <Grid item xs={12} md={4}>
          <Card sx={{ animation: 'slideInLeft 1.4s ease-out' }}>
            <CardContent sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 3, color: '#86C232', fontFamily: 'Google Sans Code, sans-serif' }}>
                Threat Distribution
              </Typography>
              {dashboardData?.threat_distribution && (
                <Typography variant="caption" sx={{ color: '#ffffff', fontFamily: 'Google Sans Code, sans-serif', mb: 2, display: 'block' }}>
                  Data points: {dashboardData.threat_distribution.length}
                </Typography>
              )}
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                                     <Pie
                     data={dashboardData?.threat_distribution || []}
                     cx="50%"
                     cy="50%"
                     labelLine={true}
                     label={({ category, percentage }) => `${category} ${percentage}%`}
                     outerRadius={80}
                     fill="#8884d8"
                     dataKey="count"
                     nameKey="category"
                   >
                    {(dashboardData?.threat_distribution || []).map((entry: any, index: number) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                                     <RechartsTooltip 
                     contentStyle={{
                       background: 'rgba(34, 38, 41, 0.95)',
                       border: '1px solid rgba(134, 194, 50, 0.5)',
                       borderRadius: 8,
                       color: '#ffffff',
                       fontSize: '12px',
                       fontWeight: 'bold',
                     }}
                     formatter={(value: any, name: any) => [value, name]}
                     labelFormatter={(label: any) => label}
                   />
                </PieChart>
              </ResponsiveContainer>
              {(!dashboardData?.threat_distribution || dashboardData.threat_distribution.length === 0) && (
                <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 200 }}>
                  <Typography variant="body2" sx={{ color: '#ffffff', fontFamily: 'Google Sans Code, sans-serif' }}>
                    No threat distribution data available
                  </Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Framework Info */}
      {systemStatus && (
        <Card sx={{ mt: 3, animation: 'fadeInUp 1.6s ease-out' }}>
          <CardContent sx={{ p: 3 }}>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 3, color: '#86C232', fontFamily: 'Google Sans Code, sans-serif' }}>
              Framework Information
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={3}>
                <Typography variant="body2" sx={{ color: '#ffffff', fontFamily: 'Google Sans Code, sans-serif' }}>
                  Approach
                </Typography>
                <Typography variant="body1" sx={{ color: '#86C232', fontFamily: 'Google Sans Code, sans-serif' }}>
                  {systemStatus.approach || "AISF Framework"}
                </Typography>
              </Grid>
              <Grid item xs={12} md={3}>
                <Typography variant="body2" sx={{ color: '#ffffff', fontFamily: 'Google Sans Code, sans-serif' }}>
                  ML Model
                </Typography>
                <Typography variant="body1" sx={{ color: '#86C232', fontFamily: 'Google Sans Code, sans-serif' }}>
                  {systemStatus.ml_model || "Random Forest"}
                </Typography>
              </Grid>
              <Grid item xs={12} md={3}>
                <Typography variant="body2" sx={{ color: '#ffffff', fontFamily: 'Google Sans Code, sans-serif' }}>
                  Enterprise Ready
                </Typography>
                <Typography variant="body1" sx={{ color: '#86C232', fontFamily: 'Google Sans Code, sans-serif' }}>
                  {systemStatus.enterprise_ready ? "Yes" : "No"}
                </Typography>
              </Grid>
              <Grid item xs={12} md={3}>
                <Typography variant="body2" sx={{ color: '#ffffff', fontFamily: 'Google Sans Code, sans-serif' }}>
                  Data Buffers
                </Typography>
                <Typography variant="body1" sx={{ color: '#86C232', fontFamily: 'Google Sans Code, sans-serif' }}>
                  {(() => {
                    const buffers = systemStatus.data_buffers || {};
                    const total = Object.values(buffers).reduce((a: any, b: any) => a + b, 0);
                    return `${total} items`;
                  })()}
                </Typography>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default Dashboard; 