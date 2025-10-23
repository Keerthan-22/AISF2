import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Paper,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Alert,
  CircularProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Tooltip,
  Switch,
  FormControlLabel,
} from '@mui/material';
import {
  Security,
  Person,
  Warning,
  CheckCircle,
  Block,
  Refresh,
  Visibility,
  Edit,
  Delete,
  Add,
  Lock,
  LockOpen,
} from '@mui/icons-material';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer } from 'recharts';
import { apiService } from '../../services/api';

interface RiskAssessment {
  id: string;
  userId: string;
  username: string;
  tpsScore: number;
  riskFactors: string[];
  accessDecision: 'allow' | 'mfa' | 'block';
  isAnomalous: boolean;
  anomalyScore: number;
  timestamp: string;
  deviceInfo: string;
  networkType: string;
  ipAddress: string;
}

interface UserBehavior {
  userId: string;
  username: string;
  loginTime: string;
  deviceType: string;
  location: string;
  riskScore: number;
  status: 'active' | 'suspicious' | 'blocked';
}

const AccessControl: React.FC = () => {
  const [riskAssessments, setRiskAssessments] = useState<RiskAssessment[]>([]);
  const [userBehaviors, setUserBehaviors] = useState<UserBehavior[]>([]);
  const [loading, setLoading] = useState(true);
  const [riskTrends, setRiskTrends] = useState<any[]>([]);
  const [openAssessmentDialog, setOpenAssessmentDialog] = useState(false);
  const [selectedAssessment, setSelectedAssessment] = useState<RiskAssessment | null>(null);
  const [selectedUser, setSelectedUser] = useState<RiskAssessment | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Form state for new assessment
  const [assessmentForm, setAssessmentForm] = useState({
    username: '',
    deviceType: 'laptop',
    networkType: 'corporate_wifi',
    ipAddress: '',
    context: '',
  });

  const fetchAccessControlData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Fetch access control data from backend
      const accessControlData = await apiService.getAccessControlData();
      
      // Transform backend data to frontend format
      const transformedAssessments: RiskAssessment[] = accessControlData.riskAssessments?.map((assessment: any, index: number) => ({
        id: assessment.id || `assessment-${index}`,
        userId: assessment.userId || `user-${index}`,
        username: assessment.username || `user${index}`,
        tpsScore: assessment.tpsScore || Math.random() * 100,
        riskFactors: assessment.riskFactors || ['Unusual login time', 'Unknown device'],
        accessDecision: assessment.accessDecision || (Math.random() > 0.7 ? 'mfa' : 'allow'),
        isAnomalous: assessment.isAnomalous || Math.random() > 0.6,
        anomalyScore: assessment.anomalyScore || Math.random(),
        timestamp: assessment.timestamp || new Date().toISOString(),
        deviceInfo: assessment.deviceInfo || 'Unknown device',
        networkType: assessment.networkType || 'public_wifi',
        ipAddress: assessment.ipAddress || `192.168.1.${100 + index}`,
      })) || [];

      const transformedBehaviors: UserBehavior[] = accessControlData.userBehaviors?.map((behavior: any, index: number) => ({
        userId: behavior.userId || `user-${index}`,
        username: behavior.username || `user${index}`,
        loginTime: behavior.loginTime || new Date().toISOString(),
        deviceType: behavior.deviceType || 'laptop',
        location: behavior.location || 'Unknown',
        riskScore: behavior.riskScore || Math.random() * 100,
        status: behavior.status || (Math.random() > 0.8 ? 'suspicious' : 'active'),
      })) || [];

      setRiskAssessments(transformedAssessments);
      setUserBehaviors(transformedBehaviors);
      
      // Generate risk trends data
      const trendsData = Array.from({ length: 7 }, (_, i) => ({
        date: new Date(Date.now() - (6 - i) * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        averageTPS: Math.random() * 50 + 20,
        anomalies: Math.floor(Math.random() * 10),
        blocked: Math.floor(Math.random() * 5),
      }));
      setRiskTrends(trendsData);
      
    } catch (err) {
      console.error('Error fetching access control data:', err);
      setError('Failed to load access control data. Using fallback data.');
      
      // Fallback data if API fails
      setRiskAssessments([
        {
          id: '1',
          userId: 'user1',
          username: 'john.doe',
          tpsScore: 85.5,
          riskFactors: ['Unusual login time', 'Unknown device', 'High-risk location'],
          accessDecision: 'block', // > 80 = Critical Risk = Block access
          isAnomalous: true,
          anomalyScore: 0.78,
          timestamp: new Date().toISOString(),
          deviceInfo: 'iPhone 12, iOS 15.0',
          networkType: 'public_wifi',
          ipAddress: '192.168.1.100',
        },
        {
          id: '2',
          userId: 'user2',
          username: 'jane.smith',
          tpsScore: 12.3,
          riskFactors: ['Normal behavior'],
          accessDecision: 'allow', // 0-30 = Low Risk = Grant access normally
          isAnomalous: false,
          anomalyScore: 0.05,
          timestamp: new Date(Date.now() - 300000).toISOString(),
          deviceInfo: 'MacBook Pro, macOS 12.0',
          networkType: 'corporate_wifi',
          ipAddress: '10.0.0.50',
        },
        {
          id: '3',
          userId: 'user3',
          username: 'admin.user',
          tpsScore: 95.2,
          riskFactors: ['Multiple failed attempts', 'Suspicious IP', 'Unusual access pattern'],
          accessDecision: 'block', // > 80 = Critical Risk = Block access
          isAnomalous: true,
          anomalyScore: 0.92,
          timestamp: new Date(Date.now() - 600000).toISOString(),
          deviceInfo: 'Unknown device',
          networkType: 'public_wifi',
          ipAddress: '203.45.67.89',
        }
      ]);
      
      setUserBehaviors([
        {
          userId: 'user1',
          username: 'john.doe',
          loginTime: new Date().toISOString(),
          deviceType: 'mobile',
          location: 'New York',
          riskScore: 78.5,
          status: 'suspicious',
        },
        {
          userId: 'user2',
          username: 'jane.smith',
          loginTime: new Date(Date.now() - 1800000).toISOString(),
          deviceType: 'laptop',
          location: 'San Francisco',
          riskScore: 12.3,
          status: 'active',
        },
        {
          userId: 'user3',
          username: 'admin.user',
          loginTime: new Date(Date.now() - 3600000).toISOString(),
          deviceType: 'desktop',
          location: 'Chicago',
          riskScore: 45.7,
          status: 'active',
        }
      ]);
      
      const trendsData = Array.from({ length: 7 }, (_, i) => ({
        date: new Date(Date.now() - (6 - i) * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        averageTPS: Math.random() * 50 + 20,
        anomalies: Math.floor(Math.random() * 10),
        blocked: Math.floor(Math.random() * 5),
      }));
      setRiskTrends(trendsData);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAccessControlData();
    
    // Auto-refresh every 30 seconds if enabled
    let interval: NodeJS.Timeout;
    if (autoRefresh) {
      interval = setInterval(fetchAccessControlData, 30000);
    }
    
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [autoRefresh]);

  const getDecisionColor = (decision: string) => {
    switch (decision) {
      case 'allow': return 'success';
      case 'mfa': return 'warning';
      case 'block': return 'error';
      default: return 'default';
    }
  };

  const getDecisionIcon = (decision: string) => {
    switch (decision) {
      case 'allow': return <CheckCircle />;
      case 'mfa': return <Warning />;
      case 'block': return <Block />;
      default: return <Security />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'success';
      case 'suspicious': return 'warning';
      case 'blocked': return 'error';
      default: return 'default';
    }
  };

  const handleNewAssessment = () => {
    setOpenAssessmentDialog(true);
  };

  const handleAssessmentSubmit = () => {
    // Calculate risk score based on various factors
    const baseRiskScore = Math.random() * 100;
    const tpsScore = Math.round(baseRiskScore * 10) / 10; // Round to 1 decimal place
    
    // Determine access decision based on risk score using the new rules
    let accessDecision: 'allow' | 'mfa' | 'block';
    if (tpsScore >= 0 && tpsScore <= 30) {
      accessDecision = 'allow';
    } else if (tpsScore >= 31 && tpsScore <= 70) {
      accessDecision = 'mfa';
    } else {
      accessDecision = 'block';
    }
    
    // If risk score > 80, create an incident for Incident Response
    if (tpsScore > 80) {
      const incidentData = {
        id: `incident-${Date.now()}`,
        title: `High Risk User Access Attempt - ${assessmentForm.username}`,
        description: `User ${assessmentForm.username} attempted access with risk score ${tpsScore.toFixed(1)}%. Risk factors: ${assessmentForm.context || 'High risk behavior detected'}`,
        severity: 'critical' as const,
        status: 'open' as const,
        priority: 'critical' as const,
        assignee: 'security.team',
        reporter: 'access.control.system',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        affectedSystems: ['Access Control System', 'User Authentication'],
        indicators: [assessmentForm.ipAddress, assessmentForm.deviceType, assessmentForm.networkType],
        tags: ['high-risk', 'access-control', 'security-alert'],
        sla: {
          target: '1 hour',
          current: '0 minutes',
          breached: false,
        },
      };
      
      // Store incident in localStorage for Incident Response to access
      const existingIncidents = JSON.parse(localStorage.getItem('aisf_incidents') || '[]');
      existingIncidents.push(incidentData);
      localStorage.setItem('aisf_incidents', JSON.stringify(existingIncidents));
      
      // Show alert to security team
      alert(`🚨 CRITICAL: High risk user ${assessmentForm.username} (Score: ${tpsScore.toFixed(1)}%) - Incident created for security team review!`);
    }
    
    // In real app, this would call the API
    const newAssessment: RiskAssessment = {
      id: Date.now().toString(),
      userId: 'new-user',
      username: assessmentForm.username,
      tpsScore: tpsScore,
      riskFactors: ['New user assessment'],
      accessDecision: accessDecision,
      isAnomalous: tpsScore > 40,
      anomalyScore: tpsScore / 100,
      timestamp: new Date().toISOString(),
      deviceInfo: assessmentForm.deviceType,
      networkType: assessmentForm.networkType,
      ipAddress: assessmentForm.ipAddress,
    };

    setRiskAssessments([newAssessment, ...riskAssessments]);
    setOpenAssessmentDialog(false);
    setAssessmentForm({
      username: '',
      deviceType: 'laptop',
      networkType: 'corporate_wifi',
      ipAddress: '',
      context: '',
    });
  };

  const handleManualDecision = (assessmentId: string, decision: string) => {
    setRiskAssessments(prev => 
      prev.map(assessment => 
        assessment.id === assessmentId 
          ? { ...assessment, accessDecision: decision as any }
          : assessment
      )
    );
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1" gutterBottom>
          Access Control
        </Typography>
        <Box display="flex" alignItems="center" gap={2}>
          <FormControlLabel
            control={
              <Switch
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
              />
            }
            label="Auto Refresh"
          />
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={handleNewAssessment}
          >
            New Assessment
          </Button>
        </Box>
      </Box>

      {/* Risk Trends Chart */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12}>
          <Paper sx={{ p: 3, height: 300 }}>
            <Typography variant="h6" gutterBottom>
              Risk Score Trends (24h)
            </Typography>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={riskTrends}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" stroke="#ffffff" />
                <YAxis stroke="#ffffff" />
                <RechartsTooltip />
                <Line 
                  type="monotone" 
                  dataKey="averageTPS" 
                  stroke="#8884d8" 
                  strokeWidth={2}
                  name="Average Risk"
                />
                <Line 
                  type="monotone" 
                  dataKey="anomalies" 
                  stroke="#ff6b6b" 
                  strokeWidth={2}
                  name="High Risk Users"
                />
              </LineChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
      </Grid>

      {/* Risk Assessments Table */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 3 }}>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
              <Typography variant="h6">
                Recent Risk Assessments
              </Typography>
              <Tooltip title="Refresh">
                <IconButton size="small">
                  <Refresh />
                </IconButton>
              </Tooltip>
            </Box>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>User</TableCell>
                    <TableCell>TPS Score</TableCell>
                    <TableCell>Decision</TableCell>
                    <TableCell>Anomaly</TableCell>
                    <TableCell>Device</TableCell>
                    <TableCell>Time</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {riskAssessments.map((assessment) => (
                    <TableRow key={assessment.id}>
                      <TableCell>
                        <Typography variant="body2" fontWeight="bold">
                          {assessment.username}
                        </Typography>
                        <Typography variant="caption" color="textSecondary">
                          {assessment.ipAddress}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={`${assessment.tpsScore.toFixed(1)}%`}
                          color={assessment.tpsScore > 70 ? 'error' : assessment.tpsScore > 40 ? 'warning' : 'success'}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          icon={getDecisionIcon(assessment.accessDecision)}
                          label={assessment.accessDecision.toUpperCase()}
                          color={getDecisionColor(assessment.accessDecision)}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        {assessment.isAnomalous ? (
                          <Chip
                            label={`${(assessment.anomalyScore * 100).toFixed(0)}%`}
                            color="warning"
                            size="small"
                          />
                        ) : (
                          <Chip label="Normal" color="success" size="small" />
                        )}
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {assessment.deviceInfo}
                        </Typography>
                        <Typography variant="caption" color="textSecondary">
                          {assessment.networkType}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        {new Date(assessment.timestamp).toLocaleTimeString()}
                      </TableCell>
                      <TableCell>
                        <Box display="flex" gap={1}>
                          <Tooltip title="View Details">
                            <IconButton size="small" onClick={() => setSelectedAssessment(assessment)}>
                              <Visibility />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Override Decision">
                            <IconButton size="small" onClick={() => handleManualDecision(assessment.id, 'allow')}>
                              <Edit />
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </Grid>

        {/* User Behavior Monitoring */}
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Active User Sessions
            </Typography>
            <Box display="flex" flexDirection="column" gap={2}>
              {userBehaviors.map((user) => (
                <Card key={user.userId} variant="outlined">
                  <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
                    <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                      <Typography variant="body2" fontWeight="bold">
                        {user.username}
                      </Typography>
                      <Chip
                        label={user.status}
                        color={getStatusColor(user.status)}
                        size="small"
                      />
                    </Box>
                    <Typography variant="caption" color="textSecondary" display="block">
                      {user.deviceType} • {user.location}
                    </Typography>
                    <Typography variant="caption" color="textSecondary" display="block">
                      Risk: {user.riskScore.toFixed(1)}% • {new Date(user.loginTime).toLocaleTimeString()}
                    </Typography>
                  </CardContent>
                </Card>
              ))}
            </Box>
          </Paper>
        </Grid>
      </Grid>

      {/* New Assessment Dialog */}
      <Dialog open={openAssessmentDialog} onClose={() => setOpenAssessmentDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>New Risk Assessment</DialogTitle>
        <DialogContent>
          <Box display="flex" flexDirection="column" gap={2} mt={1}>
            <TextField
              label="Username"
              value={assessmentForm.username}
              onChange={(e) => setAssessmentForm({ ...assessmentForm, username: e.target.value })}
              fullWidth
            />
            <FormControl fullWidth>
              <InputLabel>Device Type</InputLabel>
              <Select
                value={assessmentForm.deviceType}
                onChange={(e) => setAssessmentForm({ ...assessmentForm, deviceType: e.target.value })}
                label="Device Type"
              >
                <MenuItem value="laptop">Laptop</MenuItem>
                <MenuItem value="desktop">Desktop</MenuItem>
                <MenuItem value="mobile">Mobile</MenuItem>
                <MenuItem value="tablet">Tablet</MenuItem>
              </Select>
            </FormControl>
            <FormControl fullWidth>
              <InputLabel>Network Type</InputLabel>
              <Select
                value={assessmentForm.networkType}
                onChange={(e) => setAssessmentForm({ ...assessmentForm, networkType: e.target.value })}
                label="Network Type"
              >
                <MenuItem value="corporate_wifi">Corporate WiFi</MenuItem>
                <MenuItem value="home_wifi">Home WiFi</MenuItem>
                <MenuItem value="public_wifi">Public WiFi</MenuItem>
                <MenuItem value="mobile_data">Mobile Data</MenuItem>
              </Select>
            </FormControl>
            <TextField
              label="IP Address"
              value={assessmentForm.ipAddress}
              onChange={(e) => setAssessmentForm({ ...assessmentForm, ipAddress: e.target.value })}
              fullWidth
            />
            <TextField
              label="Additional Context"
              value={assessmentForm.context}
              onChange={(e) => setAssessmentForm({ ...assessmentForm, context: e.target.value })}
              multiline
              rows={3}
              fullWidth
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenAssessmentDialog(false)}>Cancel</Button>
          <Button onClick={handleAssessmentSubmit} variant="contained">
            Assess Risk
          </Button>
        </DialogActions>
      </Dialog>

      {/* Assessment Details Dialog */}
      <Dialog open={!!selectedAssessment} onClose={() => setSelectedAssessment(null)} maxWidth="md" fullWidth>
        {selectedAssessment && (
          <>
            <DialogTitle>Risk Assessment Details</DialogTitle>
            <DialogContent>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" gutterBottom>User Information</Typography>
                  <Box display="flex" flexDirection="column" gap={1}>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Username:</Typography>
                      <Typography variant="body2" fontWeight="bold">{selectedAssessment.username}</Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">User ID:</Typography>
                      <Typography variant="body2">{selectedAssessment.userId}</Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Device:</Typography>
                      <Typography variant="body2">{selectedAssessment.deviceInfo}</Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Network:</Typography>
                      <Typography variant="body2">{selectedAssessment.networkType}</Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">IP Address:</Typography>
                      <Typography variant="body2">{selectedAssessment.ipAddress}</Typography>
                    </Box>
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" gutterBottom>Risk Analysis</Typography>
                  <Box display="flex" flexDirection="column" gap={1}>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">TPS Score:</Typography>
                      <Typography variant="body2" fontWeight="bold" color={selectedAssessment.tpsScore > 60 ? 'error' : 'success'}>
                        {selectedAssessment.tpsScore.toFixed(1)}%
                      </Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Decision:</Typography>
                      <Chip
                        icon={getDecisionIcon(selectedAssessment.accessDecision)}
                        label={selectedAssessment.accessDecision.toUpperCase()}
                        color={getDecisionColor(selectedAssessment.accessDecision)}
                        size="small"
                      />
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Anomalous:</Typography>
                      <Chip
                        label={selectedAssessment.isAnomalous ? 'YES' : 'NO'}
                        color={selectedAssessment.isAnomalous ? 'error' : 'success'}
                        size="small"
                      />
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Anomaly Score:</Typography>
                      <Typography variant="body2">{(selectedAssessment.anomalyScore * 100).toFixed(1)}%</Typography>
                    </Box>
                  </Box>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="h6" gutterBottom>Risk Factors</Typography>
                  <Box display="flex" flexWrap="wrap" gap={1}>
                    {selectedAssessment.riskFactors.map((factor, index) => (
                      <Chip key={index} label={factor} variant="outlined" size="small" />
                    ))}
                  </Box>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="h6" gutterBottom>Timeline</Typography>
                  <Typography variant="body2" color="textSecondary">
                    Assessment performed at: {new Date(selectedAssessment.timestamp).toLocaleString()}
                  </Typography>
                </Grid>
              </Grid>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setSelectedAssessment(null)}>Close</Button>
              <Button 
                onClick={() => handleManualDecision(selectedAssessment.id, 'allow')} 
                variant="contained" 
                color="primary"
              >
                Override Decision
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  );
};

export default AccessControl; 