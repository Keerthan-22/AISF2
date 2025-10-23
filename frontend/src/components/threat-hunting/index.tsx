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
  LinearProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
} from '@mui/material';
import {
  Security,
  Search,
  Warning,
  CheckCircle,
  Error,
  Refresh,
  Visibility,
  ExpandMore,
  BugReport,
  Timeline,
  LocationOn,
  Computer,
  NetworkCheck,
  DataUsage,
  FilterList,
  PlayArrow,
  Stop,
  Download,
  Share,
} from '@mui/icons-material';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, ScatterChart, Scatter, ZAxis } from 'recharts';

interface HuntingQuery {
  id: string;
  name: string;
  description: string;
  queryType: 'apt_detection' | 'malware_analysis' | 'insider_threat' | 'network_anomaly' | 'custom';
  status: 'running' | 'completed' | 'failed' | 'scheduled';
  progress: number;
  results: number;
  startTime: string;
  endTime?: string;
  dataSource: string;
  filters: Record<string, any>;
}

interface IoCAnalysis {
  id: string;
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email';
  value: string;
  confidence: number;
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
  firstSeen: string;
  lastSeen: string;
  sources: string[];
  tags: string[];
  description: string;
}

interface BehavioralAnalysis {
  userId: string;
  username: string;
  riskScore: number;
  anomalies: string[];
  patterns: string[];
  lastActivity: string;
  deviceCount: number;
  locationCount: number;
  unusualHours: boolean;
  dataAccess: number;
}

const ThreatHunting: React.FC = () => {
  const [huntingQueries, setHuntingQueries] = useState<HuntingQuery[]>([]);
  const [iocAnalysis, setIocAnalysis] = useState<IoCAnalysis[]>([]);
  const [behavioralAnalysis, setBehavioralAnalysis] = useState<BehavioralAnalysis[]>([]);
  const [loading, setLoading] = useState(true);
  const [huntingTrends, setHuntingTrends] = useState<any[]>([]);
  const [openQueryDialog, setOpenQueryDialog] = useState(false);
  const [openIoCDialog, setOpenIoCDialog] = useState(false);
  const [selectedQuery, setSelectedQuery] = useState<HuntingQuery | null>(null);
  const [selectedIoC, setSelectedIoC] = useState<IoCAnalysis | null>(null);

  // Form state for new hunting query
  const [queryForm, setQueryForm] = useState({
    name: '',
    description: '',
    queryType: 'apt_detection' as 'apt_detection' | 'malware_analysis' | 'insider_threat' | 'network_anomaly' | 'custom',
    dataSource: 'network',
    timeRange: 'last_24_hours',
    customQuery: '',
  });

  // Form state for IoC analysis
  const [iocForm, setIocForm] = useState({
    type: 'ip' as const,
    value: '',
    description: '',
  });

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Mock data
      setHuntingQueries([
        {
          id: '1',
          name: 'APT Group Detection',
          description: 'Hunt for advanced persistent threat indicators',
          queryType: 'apt_detection',
          status: 'completed',
          progress: 100,
          results: 15,
          startTime: new Date(Date.now() - 3600000).toISOString(),
          endTime: new Date().toISOString(),
          dataSource: 'network',
          filters: { timeRange: 'last_24_hours', threatLevel: 'high' },
        },
        {
          id: '2',
          name: 'Malware C2 Communication',
          description: 'Detect command and control communication patterns',
          queryType: 'malware_analysis',
          status: 'running',
          progress: 65,
          results: 8,
          startTime: new Date(Date.now() - 1800000).toISOString(),
          dataSource: 'network',
          filters: { protocol: 'tcp', port: 443 },
        },
        {
          id: '3',
          name: 'Insider Threat Analysis',
          description: 'Identify potential insider threat behaviors',
          queryType: 'insider_threat',
          status: 'scheduled',
          progress: 0,
          results: 0,
          startTime: new Date(Date.now() + 3600000).toISOString(),
          dataSource: 'user_activity',
          filters: { userRole: 'admin', timeRange: 'last_7_days' },
        },
      ]);

      setIocAnalysis([
        {
          id: '1',
          type: 'ip',
          value: '192.168.1.100',
          confidence: 95.2,
          threatLevel: 'high',
          firstSeen: new Date(Date.now() - 86400000).toISOString(),
          lastSeen: new Date().toISOString(),
          sources: ['ThreatFox', 'AbuseIPDB', 'VirusTotal'],
          tags: ['malware', 'c2', 'apt'],
          description: 'Known C2 server for Emotet malware family',
        },
        {
          id: '2',
          type: 'domain',
          value: 'malicious-domain.com',
          confidence: 87.3,
          threatLevel: 'medium',
          firstSeen: new Date(Date.now() - 172800000).toISOString(),
          lastSeen: new Date(Date.now() - 3600000).toISOString(),
          sources: ['URLhaus', 'PhishTank'],
          tags: ['phishing', 'malware'],
          description: 'Phishing domain distributing credential stealers',
        },
        {
          id: '3',
          type: 'hash',
          value: 'a1b2c3d4e5f6789012345678901234567890abcd',
          confidence: 98.7,
          threatLevel: 'critical',
          firstSeen: new Date(Date.now() - 259200000).toISOString(),
          lastSeen: new Date(Date.now() - 7200000).toISOString(),
          sources: ['VirusTotal', 'MalwareBazaar', 'Hybrid Analysis'],
          tags: ['ransomware', 'critical'],
          description: 'Ransomware payload - WannaCry variant',
        },
      ]);

      setBehavioralAnalysis([
        {
          userId: 'user1',
          username: 'john.doe',
          riskScore: 85.5,
          anomalies: ['Unusual login times', 'Multiple failed attempts', 'Data exfiltration'],
          patterns: ['After-hours access', 'Bulk data download', 'External device usage'],
          lastActivity: new Date().toISOString(),
          deviceCount: 5,
          locationCount: 3,
          unusualHours: true,
          dataAccess: 1500,
        },
        {
          userId: 'user2',
          username: 'jane.smith',
          riskScore: 12.3,
          anomalies: [],
          patterns: ['Regular work hours', 'Normal data access patterns'],
          lastActivity: new Date(Date.now() - 3600000).toISOString(),
          deviceCount: 2,
          locationCount: 1,
          unusualHours: false,
          dataAccess: 250,
        },
        {
          userId: 'user3',
          username: 'admin.user',
          riskScore: 92.1,
          anomalies: ['Privilege escalation', 'Suspicious file access', 'Network scanning'],
          patterns: ['Administrative actions', 'System configuration changes'],
          lastActivity: new Date(Date.now() - 1800000).toISOString(),
          deviceCount: 8,
          locationCount: 4,
          unusualHours: true,
          dataAccess: 5000,
        },
      ]);

      setHuntingTrends([
        { time: '00:00', queries: 5, findings: 12 },
        { time: '04:00', queries: 3, findings: 8 },
        { time: '08:00', queries: 8, findings: 25 },
        { time: '12:00', queries: 12, findings: 42 },
        { time: '16:00', queries: 10, findings: 35 },
        { time: '20:00', queries: 7, findings: 18 },
      ]);

      setLoading(false);
    };

    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30 seconds

    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'warning';
      case 'completed': return 'success';
      case 'failed': return 'error';
      case 'scheduled': return 'info';
      default: return 'default';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running': return <PlayArrow />;
      case 'completed': return <CheckCircle />;
      case 'failed': return <Error />;
      case 'scheduled': return <Timeline />;
      default: return <Security />;
    }
  };

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'low': return 'success';
      case 'medium': return 'warning';
      case 'high': return 'error';
      case 'critical': return 'error';
      default: return 'default';
    }
  };

  const getIoCIcon = (type: string) => {
    switch (type) {
      case 'ip': return <Computer />;
      case 'domain': return <NetworkCheck />;
      case 'url': return <DataUsage />;
      case 'hash': return <BugReport />;
      case 'email': return <Security />;
      default: return <Security />;
    }
  };

  const handleNewQuery = () => {
    setOpenQueryDialog(true);
  };

  const handleQuerySubmit = () => {
    // In real app, this would call the API
    const newQuery: HuntingQuery = {
      id: Date.now().toString(),
      name: queryForm.name,
      description: queryForm.description,
      queryType: queryForm.queryType,
      status: 'scheduled',
      progress: 0,
      results: 0,
      startTime: new Date(Date.now() + 60000).toISOString(), // Start in 1 minute
      dataSource: queryForm.dataSource,
      filters: { timeRange: queryForm.timeRange },
    };

    setHuntingQueries([newQuery, ...huntingQueries]);
    setOpenQueryDialog(false);
    setQueryForm({
      name: '',
      description: '',
      queryType: 'apt_detection',
      dataSource: 'network',
      timeRange: 'last_24_hours',
      customQuery: '',
    });
  };

  const handleNewIoCAnalysis = () => {
    setOpenIoCDialog(true);
  };

  const handleIoCAnalysisSubmit = () => {
    // In real app, this would call the API
    const newIoC: IoCAnalysis = {
      id: Date.now().toString(),
      type: iocForm.type,
      value: iocForm.value,
      confidence: Math.random() * 100,
      threatLevel: Math.random() > 0.7 ? 'high' : 'medium',
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      sources: ['Manual Analysis'],
      tags: ['manual'],
      description: iocForm.description,
    };

    setIocAnalysis([newIoC, ...iocAnalysis]);
    setOpenIoCDialog(false);
    setIocForm({
      type: 'ip',
      value: '',
      description: '',
    });
  };

  const handleStartQuery = (queryId: string) => {
    setHuntingQueries(prev => 
      prev.map(query => 
        query.id === queryId 
          ? { ...query, status: 'running', progress: 0 }
          : query
      )
    );
  };

  const handleStopQuery = (queryId: string) => {
    setHuntingQueries(prev => 
      prev.map(query => 
        query.id === queryId 
          ? { ...query, status: 'completed', progress: 100, endTime: new Date().toISOString() }
          : query
      )
    );
  };

  const handleDownloadResults = (queryId: string) => {
    // In real app, this would generate and download a report
    alert(`Downloading results for query: ${queryId}`);
  };

  const handleShareIoC = (ioc: IoCAnalysis) => {
    // In real app, this would share the IoC with other systems
    alert(`Sharing IoC: ${ioc.value} (${ioc.type})`);
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
          Threat Hunting
        </Typography>
        <Box display="flex" gap={2}>
          <Button
            variant="outlined"
            startIcon={<BugReport />}
            onClick={handleNewIoCAnalysis}
          >
            IoC Analysis
          </Button>
          <Button
            variant="contained"
            startIcon={<Search />}
            onClick={handleNewQuery}
          >
            New Hunt
          </Button>
        </Box>
      </Box>

      {/* Hunting Trends Chart */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12}>
          <Paper sx={{ p: 3, height: 300 }}>
            <Typography variant="h6" gutterBottom>
              Hunting Activity Trends (24h)
            </Typography>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={huntingTrends}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" stroke="#ffffff" />
                <YAxis yAxisId="left" stroke="#ffffff" />
                <YAxis yAxisId="right" orientation="right" stroke="#ffffff" />
                <RechartsTooltip />
                <Line 
                  yAxisId="left"
                  type="monotone" 
                  dataKey="queries" 
                  stroke="#8884d8" 
                  strokeWidth={2}
                  name="Active Queries"
                />
                <Line 
                  yAxisId="right"
                  type="monotone" 
                  dataKey="findings" 
                  stroke="#82ca9d" 
                  strokeWidth={2}
                  name="Findings"
                />
              </LineChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
      </Grid>

      {/* Active Hunting Queries */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
              <Typography variant="h6">
                Active Hunting Queries
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
                    <TableCell>Query Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Progress</TableCell>
                    <TableCell>Results</TableCell>
                    <TableCell>Data Source</TableCell>
                    <TableCell>Start Time</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {huntingQueries.map((query) => (
                    <TableRow key={query.id}>
                      <TableCell>
                        <Typography variant="body2" fontWeight="bold">
                          {query.name}
                        </Typography>
                        <Typography variant="caption" color="textSecondary">
                          {query.description}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={query.queryType.replace('_', ' ').toUpperCase()}
                          size="small"
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          icon={getStatusIcon(query.status)}
                          label={query.status.toUpperCase()}
                          color={getStatusColor(query.status)}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center" gap={1}>
                          <LinearProgress
                            variant="determinate"
                            value={query.progress}
                            sx={{ width: 60, height: 8, borderRadius: 4 }}
                          />
                          <Typography variant="body2">
                            {query.progress}%
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" fontWeight="bold">
                          {query.results}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="textSecondary">
                          {query.dataSource}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        {new Date(query.startTime).toLocaleTimeString()}
                      </TableCell>
                      <TableCell>
                        <Box display="flex" gap={1}>
                          <Tooltip title="View Details">
                            <IconButton 
                              size="small"
                              onClick={() => setSelectedQuery(query)}
                            >
                              <Visibility />
                            </IconButton>
                          </Tooltip>
                          {query.status === 'scheduled' && (
                            <Tooltip title="Start Query">
                              <IconButton 
                                size="small"
                                onClick={() => handleStartQuery(query.id)}
                              >
                                <PlayArrow />
                              </IconButton>
                            </Tooltip>
                          )}
                          {query.status === 'running' && (
                            <Tooltip title="Stop Query">
                              <IconButton 
                                size="small"
                                onClick={() => handleStopQuery(query.id)}
                              >
                                <Stop />
                              </IconButton>
                            </Tooltip>
                          )}
                          <Tooltip title="Download Results">
                            <IconButton size="small" onClick={() => handleDownloadResults(query.id)}>
                              <Download />
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
      </Grid>

      {/* IoC Analysis and Behavioral Analysis */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
              <Typography variant="h6">
                IoC Analysis
              </Typography>
              <Tooltip title="Refresh">
                <IconButton size="small">
                  <Refresh />
                </IconButton>
              </Tooltip>
            </Box>
            <Box display="flex" flexDirection="column" gap={2}>
              {iocAnalysis.map((ioc) => (
                <Card key={ioc.id} variant="outlined">
                  <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
                    <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                      <Box display="flex" alignItems="center" gap={1}>
                        {getIoCIcon(ioc.type)}
                        <Typography variant="body2" fontWeight="bold">
                          {ioc.value}
                        </Typography>
                      </Box>
                      <Chip
                        label={ioc.threatLevel.toUpperCase()}
                        color={getThreatLevelColor(ioc.threatLevel)}
                        size="small"
                      />
                    </Box>
                    <Typography variant="caption" color="textSecondary" display="block">
                      {ioc.description}
                    </Typography>
                    <Box display="flex" justifyContent="space-between" alignItems="center" mt={1}>
                      <Typography variant="caption" color="textSecondary">
                        Confidence: {ioc.confidence.toFixed(1)}%
                      </Typography>
                      <Box display="flex" gap={1}>
                        <Tooltip title="View Details">
                          <IconButton 
                            size="small"
                            onClick={() => setSelectedIoC(ioc)}
                          >
                            <Visibility />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Share">
                          <IconButton size="small" onClick={() => handleShareIoC(ioc)}>
                            <Share />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    </Box>
                  </CardContent>
                </Card>
              ))}
            </Box>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Behavioral Analysis
            </Typography>
            <Box display="flex" flexDirection="column" gap={2}>
              {behavioralAnalysis.map((user) => (
                <Card key={user.userId} variant="outlined">
                  <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
                    <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                      <Typography variant="body2" fontWeight="bold">
                        {user.username}
                      </Typography>
                      <Chip
                        label={`${user.riskScore.toFixed(1)}% Risk`}
                        color={user.riskScore > 70 ? 'error' : user.riskScore > 40 ? 'warning' : 'success'}
                        size="small"
                      />
                    </Box>
                    <Box display="flex" flexDirection="column" gap={0.5}>
                      <Typography variant="caption" color="textSecondary">
                        Devices: {user.deviceCount} • Locations: {user.locationCount}
                      </Typography>
                      <Typography variant="caption" color="textSecondary">
                        Data Access: {user.dataAccess} files • Last: {new Date(user.lastActivity).toLocaleTimeString()}
                      </Typography>
                      {user.anomalies.length > 0 && (
                        <Box mt={1}>
                          <Typography variant="caption" color="error" fontWeight="bold">
                            Anomalies: {user.anomalies.join(', ')}
                          </Typography>
                        </Box>
                      )}
                    </Box>
                  </CardContent>
                </Card>
              ))}
            </Box>
          </Paper>
        </Grid>
      </Grid>

      {/* New Hunting Query Dialog */}
      <Dialog open={openQueryDialog} onClose={() => setOpenQueryDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>New Hunting Query</DialogTitle>
        <DialogContent>
          <Box display="flex" flexDirection="column" gap={2} mt={1}>
            <TextField
              label="Query Name"
              value={queryForm.name}
              onChange={(e) => setQueryForm({ ...queryForm, name: e.target.value })}
              fullWidth
            />
            <TextField
              label="Description"
              value={queryForm.description}
              onChange={(e) => setQueryForm({ ...queryForm, description: e.target.value })}
              multiline
              rows={3}
              fullWidth
            />
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Query Type</InputLabel>
                  <Select
                    value={queryForm.queryType}
                    onChange={(e) => setQueryForm({ ...queryForm, queryType: e.target.value as any })}
                    label="Query Type"
                  >
                    <MenuItem value="apt_detection">APT Detection</MenuItem>
                    <MenuItem value="malware_analysis">Malware Analysis</MenuItem>
                    <MenuItem value="insider_threat">Insider Threat</MenuItem>
                    <MenuItem value="network_anomaly">Network Anomaly</MenuItem>
                    <MenuItem value="custom">Custom Query</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Data Source</InputLabel>
                  <Select
                    value={queryForm.dataSource}
                    onChange={(e) => setQueryForm({ ...queryForm, dataSource: e.target.value })}
                    label="Data Source"
                  >
                    <MenuItem value="network">Network Traffic</MenuItem>
                    <MenuItem value="user_activity">User Activity</MenuItem>
                    <MenuItem value="system_logs">System Logs</MenuItem>
                    <MenuItem value="endpoint_data">Endpoint Data</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
            <FormControl fullWidth>
              <InputLabel>Time Range</InputLabel>
              <Select
                value={queryForm.timeRange}
                onChange={(e) => setQueryForm({ ...queryForm, timeRange: e.target.value })}
                label="Time Range"
              >
                <MenuItem value="last_hour">Last Hour</MenuItem>
                <MenuItem value="last_24_hours">Last 24 Hours</MenuItem>
                <MenuItem value="last_7_days">Last 7 Days</MenuItem>
                <MenuItem value="last_30_days">Last 30 Days</MenuItem>
                <MenuItem value="custom">Custom Range</MenuItem>
              </Select>
            </FormControl>
            {queryForm.queryType === 'custom' && (
              <TextField
                label="Custom Query"
                value={queryForm.customQuery}
                onChange={(e) => setQueryForm({ ...queryForm, customQuery: e.target.value })}
                multiline
                rows={4}
                fullWidth
                placeholder="Enter your custom hunting query..."
              />
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenQueryDialog(false)}>Cancel</Button>
          <Button onClick={handleQuerySubmit} variant="contained">
            Create Query
          </Button>
        </DialogActions>
      </Dialog>

      {/* IoC Analysis Dialog */}
      <Dialog open={openIoCDialog} onClose={() => setOpenIoCDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>IoC Analysis</DialogTitle>
        <DialogContent>
          <Box display="flex" flexDirection="column" gap={2} mt={1}>
            <FormControl fullWidth>
              <InputLabel>IoC Type</InputLabel>
              <Select
                value={iocForm.type}
                onChange={(e) => setIocForm({ ...iocForm, type: e.target.value as any })}
                label="IoC Type"
              >
                <MenuItem value="ip">IP Address</MenuItem>
                <MenuItem value="domain">Domain</MenuItem>
                <MenuItem value="url">URL</MenuItem>
                <MenuItem value="hash">File Hash</MenuItem>
                <MenuItem value="email">Email Address</MenuItem>
              </Select>
            </FormControl>
            <TextField
              label="IoC Value"
              value={iocForm.value}
              onChange={(e) => setIocForm({ ...iocForm, value: e.target.value })}
              fullWidth
              placeholder={`Enter ${iocForm.type.toUpperCase()}...`}
            />
            <TextField
              label="Description (Optional)"
              value={iocForm.description}
              onChange={(e) => setIocForm({ ...iocForm, description: e.target.value })}
              multiline
              rows={3}
              fullWidth
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenIoCDialog(false)}>Cancel</Button>
          <Button onClick={handleIoCAnalysisSubmit} variant="contained">
            Analyze IoC
          </Button>
        </DialogActions>
      </Dialog>

      {/* Query Details Dialog */}
      <Dialog 
        open={!!selectedQuery} 
        onClose={() => setSelectedQuery(null)} 
        maxWidth="md" 
        fullWidth
      >
        {selectedQuery && (
          <>
            <DialogTitle>Query Details: {selectedQuery.name}</DialogTitle>
            <DialogContent>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" gutterBottom>Query Information</Typography>
                  <Box display="flex" flexDirection="column" gap={1}>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Status:</Typography>
                      <Chip
                        icon={getStatusIcon(selectedQuery.status)}
                        label={selectedQuery.status.toUpperCase()}
                        color={getStatusColor(selectedQuery.status)}
                        size="small"
                      />
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Type:</Typography>
                      <Typography variant="body2" fontWeight="bold">
                        {selectedQuery.queryType.replace('_', ' ').toUpperCase()}
                      </Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Data Source:</Typography>
                      <Typography variant="body2" fontWeight="bold">
                        {selectedQuery.dataSource}
                      </Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Results:</Typography>
                      <Typography variant="body2" fontWeight="bold">
                        {selectedQuery.results}
                      </Typography>
                    </Box>
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" gutterBottom>Progress</Typography>
                  <Box display="flex" flexDirection="column" gap={1}>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Progress:</Typography>
                      <Typography variant="body2" fontWeight="bold">
                        {selectedQuery.progress}%
                      </Typography>
                    </Box>
                    <LinearProgress
                      variant="determinate"
                      value={selectedQuery.progress}
                      sx={{ height: 10, borderRadius: 5 }}
                    />
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Start Time:</Typography>
                      <Typography variant="body2" fontWeight="bold">
                        {new Date(selectedQuery.startTime).toLocaleString()}
                      </Typography>
                    </Box>
                    {selectedQuery.endTime && (
                      <Box display="flex" justifyContent="space-between">
                        <Typography variant="body2">End Time:</Typography>
                        <Typography variant="body2" fontWeight="bold">
                          {new Date(selectedQuery.endTime).toLocaleString()}
                        </Typography>
                      </Box>
                    )}
                  </Box>
                </Grid>
                <Grid item xs={12}>
                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMore />}>
                      <Typography variant="h6">Query Filters</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Box display="flex" flexWrap="wrap" gap={1}>
                        {Object.entries(selectedQuery.filters).map(([key, value]) => (
                          <Chip
                            key={key}
                            label={`${key}: ${value}`}
                            variant="outlined"
                            size="small"
                          />
                        ))}
                      </Box>
                    </AccordionDetails>
                  </Accordion>
                </Grid>
              </Grid>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setSelectedQuery(null)}>Close</Button>
              <Button variant="contained" startIcon={<Download />}>
                Export Results
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>

      {/* IoC Details Dialog */}
      <Dialog 
        open={!!selectedIoC} 
        onClose={() => setSelectedIoC(null)} 
        maxWidth="md" 
        fullWidth
      >
        {selectedIoC && (
          <>
            <DialogTitle>IoC Details: {selectedIoC.value}</DialogTitle>
            <DialogContent>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" gutterBottom>IoC Information</Typography>
                  <Box display="flex" flexDirection="column" gap={1}>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Type:</Typography>
                      <Typography variant="body2" fontWeight="bold">
                        {selectedIoC.type.toUpperCase()}
                      </Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Threat Level:</Typography>
                      <Chip
                        label={selectedIoC.threatLevel.toUpperCase()}
                        color={getThreatLevelColor(selectedIoC.threatLevel)}
                        size="small"
                      />
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Confidence:</Typography>
                      <Typography variant="body2" fontWeight="bold">
                        {selectedIoC.confidence.toFixed(1)}%
                      </Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">First Seen:</Typography>
                      <Typography variant="body2" fontWeight="bold">
                        {new Date(selectedIoC.firstSeen).toLocaleString()}
                      </Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Last Seen:</Typography>
                      <Typography variant="body2" fontWeight="bold">
                        {new Date(selectedIoC.lastSeen).toLocaleString()}
                      </Typography>
                    </Box>
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" gutterBottom>Sources & Tags</Typography>
                  <Box display="flex" flexDirection="column" gap={2}>
                    <Box>
                      <Typography variant="body2" fontWeight="bold" gutterBottom>
                        Sources:
                      </Typography>
                      <Box display="flex" flexWrap="wrap" gap={1}>
                        {selectedIoC.sources.map((source) => (
                          <Chip key={source} label={source} size="small" variant="outlined" />
                        ))}
                      </Box>
                    </Box>
                    <Box>
                      <Typography variant="body2" fontWeight="bold" gutterBottom>
                        Tags:
                      </Typography>
                      <Box display="flex" flexWrap="wrap" gap={1}>
                        {selectedIoC.tags.map((tag) => (
                          <Chip key={tag} label={tag} size="small" color="primary" />
                        ))}
                      </Box>
                    </Box>
                  </Box>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="h6" gutterBottom>Description</Typography>
                  <Typography variant="body2">
                    {selectedIoC.description}
                  </Typography>
                </Grid>
              </Grid>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setSelectedIoC(null)}>Close</Button>
              <Button variant="contained" startIcon={<Share />}>
                Share IoC
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  );
};

export default ThreatHunting; 