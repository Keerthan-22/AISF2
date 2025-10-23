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
  Stepper,
  Step,
  StepLabel,
  StepContent,
} from '@mui/material';
import {
  Security,
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
  Assignment,
  Person,
  Schedule,
  PriorityHigh,
  LowPriority,
  TrendingUp,
} from '@mui/icons-material';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';

interface Incident {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';
  priority: 'low' | 'medium' | 'high' | 'critical';
  assignee: string;
  reporter: string;
  createdAt: string;
  updatedAt: string;
  affectedSystems: string[];
  indicators: string[];
  tags: string[];
  sla: {
    target: string;
    current: string;
    breached: boolean;
  };
}

interface ResponseWorkflow {
  id: string;
  incidentId: string;
  step: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  assignee: string;
  description: string;
  startTime: string;
  endTime?: string;
  notes: string[];
}

interface ResponseMetrics {
  totalIncidents: number;
  openIncidents: number;
  resolvedIncidents: number;
  avgResolutionTime: number;
  slaCompliance: number;
  mttr: number; // Mean Time to Resolution
  mtta: number; // Mean Time to Acknowledge
}

const IncidentResponse: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [workflows, setWorkflows] = useState<ResponseWorkflow[]>([]);
  const [metrics, setMetrics] = useState<ResponseMetrics>({
    totalIncidents: 0,
    openIncidents: 0,
    resolvedIncidents: 0,
    avgResolutionTime: 0,
    slaCompliance: 0,
    mttr: 0,
    mtta: 0,
  });
  const [loading, setLoading] = useState(true);
  const [incidentTrends, setIncidentTrends] = useState<any[]>([]);
  const [openIncidentDialog, setOpenIncidentDialog] = useState(false);
  const [openWorkflowDialog, setOpenWorkflowDialog] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [selectedWorkflow, setSelectedWorkflow] = useState<ResponseWorkflow | null>(null);

  // Form state for new incident
  const [incidentForm, setIncidentForm] = useState({
    title: '',
    description: '',
    severity: 'medium' as const,
    priority: 'medium' as const,
    assignee: '',
    affectedSystems: '',
    indicators: '',
    tags: '',
  });

  // Form state for new workflow
  const [workflowForm, setWorkflowForm] = useState({
    step: '',
    description: '',
    assignee: '',
    notes: '',
  });

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Mock data
      setIncidents([
        {
          id: '1',
          title: 'Suspicious Network Activity Detected',
          description: 'Multiple failed login attempts from unknown IP addresses detected on critical systems.',
          severity: 'high',
          status: 'investigating',
          priority: 'high',
          assignee: 'john.doe',
          reporter: 'system.alert',
          createdAt: new Date(Date.now() - 3600000).toISOString(),
          updatedAt: new Date().toISOString(),
          affectedSystems: ['Web Server', 'Database Server', 'Authentication Service'],
          indicators: ['192.168.1.100', 'malicious-domain.com', 'suspicious-hash-123'],
          tags: ['network', 'authentication', 'critical'],
          sla: {
            target: '4 hours',
            current: '1 hour 30 minutes',
            breached: false,
          },
        },
        {
          id: '2',
          title: 'Malware Detection on Endpoint',
          description: 'Antivirus software detected potential malware on user workstation.',
          severity: 'medium',
          status: 'contained',
          priority: 'medium',
          assignee: 'jane.smith',
          reporter: 'antivirus.system',
          createdAt: new Date(Date.now() - 7200000).toISOString(),
          updatedAt: new Date(Date.now() - 1800000).toISOString(),
          affectedSystems: ['Workstation-001', 'File Server'],
          indicators: ['malware-hash-456', 'suspicious-process.exe'],
          tags: ['malware', 'endpoint', 'contained'],
          sla: {
            target: '8 hours',
            current: '2 hours 15 minutes',
            breached: false,
          },
        },
        {
          id: '3',
          title: 'Data Exfiltration Attempt',
          description: 'Large data transfer detected to external destination during off-hours.',
          severity: 'critical',
          status: 'open',
          priority: 'critical',
          assignee: 'admin.user',
          reporter: 'dlp.system',
          createdAt: new Date(Date.now() - 1800000).toISOString(),
          updatedAt: new Date().toISOString(),
          affectedSystems: ['File Server', 'Database Server', 'Backup System'],
          indicators: ['10.0.0.50', 'external-server.com', 'large-transfer.log'],
          tags: ['data-exfiltration', 'critical', 'dlp'],
          sla: {
            target: '1 hour',
            current: '30 minutes',
            breached: false,
          },
        },
      ]);

      setWorkflows([
        {
          id: '1',
          incidentId: '1',
          step: 'Initial Assessment',
          status: 'completed',
          assignee: 'john.doe',
          description: 'Analyze network logs and identify source of suspicious activity',
          startTime: new Date(Date.now() - 3600000).toISOString(),
          endTime: new Date(Date.now() - 3000000).toISOString(),
          notes: ['Confirmed multiple failed login attempts', 'IP addresses traced to known threat actor'],
        },
        {
          id: '2',
          incidentId: '1',
          step: 'Containment',
          status: 'in_progress',
          assignee: 'john.doe',
          description: 'Block suspicious IP addresses and implement additional monitoring',
          startTime: new Date(Date.now() - 3000000).toISOString(),
          notes: ['Firewall rules updated', 'Additional logging enabled'],
        },
        {
          id: '3',
          incidentId: '2',
          step: 'Malware Analysis',
          status: 'completed',
          assignee: 'jane.smith',
          description: 'Analyze detected malware and determine scope of infection',
          startTime: new Date(Date.now() - 7200000).toISOString(),
          endTime: new Date(Date.now() - 5400000).toISOString(),
          notes: ['Malware identified as trojan variant', 'No other systems affected'],
        },
        {
          id: '4',
          incidentId: '2',
          step: 'System Restoration',
          status: 'completed',
          assignee: 'jane.smith',
          description: 'Remove malware and restore system to clean state',
          startTime: new Date(Date.now() - 5400000).toISOString(),
          endTime: new Date(Date.now() - 1800000).toISOString(),
          notes: ['Malware removed successfully', 'System restored from backup'],
        },
      ]);

      setMetrics({
        totalIncidents: 156,
        openIncidents: 8,
        resolvedIncidents: 142,
        avgResolutionTime: 4.5,
        slaCompliance: 94.2,
        mttr: 4.5,
        mtta: 0.8,
      });

      setIncidentTrends([
        { time: '00:00', incidents: 2, resolved: 1 },
        { time: '04:00', incidents: 1, resolved: 0 },
        { time: '08:00', incidents: 5, resolved: 3 },
        { time: '12:00', incidents: 8, resolved: 6 },
        { time: '16:00', incidents: 6, resolved: 4 },
        { time: '20:00', incidents: 3, resolved: 2 },
      ]);

      setLoading(false);
    };

    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30 seconds

    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'low': return 'success';
      case 'medium': return 'warning';
      case 'high': return 'error';
      case 'critical': return 'error';
      default: return 'default';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
          case 'low': return <LowPriority />;
    case 'medium': return <TrendingUp />;
      case 'high': return <PriorityHigh />;
      case 'critical': return <PriorityHigh />;
      default: return <Warning />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'error';
      case 'investigating': return 'warning';
      case 'contained': return 'info';
      case 'resolved': return 'success';
      case 'closed': return 'default';
      default: return 'default';
    }
  };

  const getWorkflowStatusColor = (status: string) => {
    switch (status) {
      case 'pending': return 'default';
      case 'in_progress': return 'warning';
      case 'completed': return 'success';
      case 'failed': return 'error';
      default: return 'default';
    }
  };

  const getWorkflowStatusIcon = (status: string) => {
    switch (status) {
      case 'pending': return <Schedule />;
      case 'in_progress': return <PlayArrow />;
      case 'completed': return <CheckCircle />;
      case 'failed': return <Error />;
      default: return <Assignment />;
    }
  };

  const handleNewIncident = () => {
    setOpenIncidentDialog(true);
  };

  const handleIncidentSubmit = () => {
    // In real app, this would call the API
    const newIncident: Incident = {
      id: Date.now().toString(),
      title: incidentForm.title,
      description: incidentForm.description,
      severity: incidentForm.severity,
      status: 'open',
      priority: incidentForm.priority,
      assignee: incidentForm.assignee,
      reporter: 'manual.entry',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      affectedSystems: incidentForm.affectedSystems.split(',').map(s => s.trim()),
      indicators: incidentForm.indicators.split(',').map(s => s.trim()),
      tags: incidentForm.tags.split(',').map(s => s.trim()),
      sla: {
        target: '4 hours',
        current: '0 minutes',
        breached: false,
      },
    };

    setIncidents([newIncident, ...incidents]);
    setOpenIncidentDialog(false);
    setIncidentForm({
      title: '',
      description: '',
      severity: 'medium',
      priority: 'medium',
      assignee: '',
      affectedSystems: '',
      indicators: '',
      tags: '',
    });
  };

  const handleNewWorkflow = () => {
    setOpenWorkflowDialog(true);
  };

  const handleWorkflowSubmit = () => {
    // In real app, this would call the API
    const newWorkflow: ResponseWorkflow = {
      id: Date.now().toString(),
      incidentId: selectedIncident?.id || '1',
      step: workflowForm.step,
      status: 'pending',
      assignee: workflowForm.assignee,
      description: workflowForm.description,
      startTime: new Date().toISOString(),
      notes: workflowForm.notes ? [workflowForm.notes] : [],
    };

    setWorkflows([newWorkflow, ...workflows]);
    setOpenWorkflowDialog(false);
    setWorkflowForm({
      step: '',
      description: '',
      assignee: '',
      notes: '',
    });
  };

  const handleUpdateIncidentStatus = (incidentId: string, newStatus: string) => {
    setIncidents(prev => 
      prev.map(incident => 
        incident.id === incidentId 
          ? { ...incident, status: newStatus as any, updatedAt: new Date().toISOString() }
          : incident
      )
    );
  };

  const handleUpdateWorkflowStatus = (workflowId: string, newStatus: string) => {
    setWorkflows(prev => 
      prev.map(workflow => 
        workflow.id === workflowId 
          ? { 
              ...workflow, 
              status: newStatus as any, 
              endTime: newStatus === 'completed' ? new Date().toISOString() : workflow.endTime 
            }
          : workflow
      )
    );
  };

  const handleDownloadIncidentReport = (incident: Incident) => {
    // Generate incident report content
    const reportContent = `
INCIDENT REPORT
===============

Incident ID: ${incident.id}
Title: ${incident.title}
Description: ${incident.description}
Severity: ${incident.severity.toUpperCase()}
Status: ${incident.status.toUpperCase()}
Priority: ${incident.priority.toUpperCase()}

ASSIGNMENT DETAILS
==================
Assignee: ${incident.assignee}
Reporter: ${incident.reporter}
Created: ${new Date(incident.createdAt).toLocaleString()}
Updated: ${new Date(incident.updatedAt).toLocaleString()}

AFFECTED SYSTEMS
================
${incident.affectedSystems.join('\n')}

INDICATORS
==========
${incident.indicators.join('\n')}

TAGS
=====
${incident.tags.join(', ')}

SLA INFORMATION
===============
Target: ${incident.sla.target}
Current: ${incident.sla.current}
Breached: ${incident.sla.breached ? 'YES' : 'NO'}

REPORT GENERATED
================
Date: ${new Date().toLocaleString()}
Generated by: AISF Security Platform
    `;

    // Create and download the file
    const blob = new Blob([reportContent], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `incident-report-${incident.id}-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
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
          Incident Response
        </Typography>
        <Box display="flex" gap={2}>
          <Button
            variant="outlined"
            startIcon={<Assignment />}
            onClick={handleNewWorkflow}
          >
            New Workflow
          </Button>
          <Button
            variant="contained"
            startIcon={<BugReport />}
            onClick={handleNewIncident}
          >
            New Incident
          </Button>
        </Box>
      </Box>

      {/* Response Metrics */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="body2">
                    Total Incidents
                  </Typography>
                  <Typography variant="h4" component="div">
                    {metrics.totalIncidents}
                  </Typography>
                </Box>
                <Box color="primary.main">
                  <BugReport />
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="body2">
                    Open Incidents
                  </Typography>
                  <Typography variant="h4" component="div" color="error">
                    {metrics.openIncidents}
                  </Typography>
                </Box>
                <Box color="error.main">
                  <Warning />
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="body2">
                    SLA Compliance
                  </Typography>
                  <Typography variant="h4" component="div" color="success.main">
                    {metrics.slaCompliance}%
                  </Typography>
                </Box>
                <Box color="success.main">
                  <CheckCircle />
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="body2">
                    Avg Resolution Time
                  </Typography>
                  <Typography variant="h4" component="div">
                    {metrics.avgResolutionTime}h
                  </Typography>
                </Box>
                <Box color="info.main">
                  <Timeline />
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Incident Trends Chart */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12}>
          <Paper sx={{ p: 3, height: 300 }}>
            <Typography variant="h6" gutterBottom>
              Incident Trends (24h)
            </Typography>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={incidentTrends}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" stroke="#ffffff" />
                <YAxis stroke="#ffffff" />
                <RechartsTooltip />
                <Line 
                  type="monotone" 
                  dataKey="incidents" 
                  stroke="#ff6b6b" 
                  strokeWidth={2}
                  name="New Incidents"
                />
                <Line 
                  type="monotone" 
                  dataKey="resolved" 
                  stroke="#4ecdc4" 
                  strokeWidth={2}
                  name="Resolved Incidents"
                />
              </LineChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
      </Grid>

      {/* Active Incidents */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 3 }}>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
              <Typography variant="h6">
                Active Incidents
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
                    <TableCell>Incident</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Assignee</TableCell>
                    <TableCell>SLA</TableCell>
                    <TableCell>Created</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {incidents.map((incident) => (
                    <TableRow key={incident.id}>
                      <TableCell>
                        <Typography variant="body2" fontWeight="bold">
                          {incident.title}
                        </Typography>
                        <Typography variant="caption" color="textSecondary">
                           {incident.description.substring(0, 50)}...
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          icon={getSeverityIcon(incident.severity)}
                          label={incident.severity.toUpperCase()}
                          color={getSeverityColor(incident.severity)}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={incident.status.toUpperCase()}
                          color={getStatusColor(incident.status)}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {incident.assignee}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Box display="flex" flexDirection="column">
                        <Typography variant="caption" color="textSecondary">
                            Target: {incident.sla.target}
                        </Typography>
                          <Typography variant="caption" color={incident.sla.breached ? 'error' : 'success'}>
                            Current: {incident.sla.current}
                        </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        {new Date(incident.createdAt).toLocaleTimeString()}
                      </TableCell>
                      <TableCell>
                        <Box display="flex" gap={1}>
                          <Tooltip title="View Details">
                            <IconButton 
                              size="small"
                              onClick={() => setSelectedIncident(incident)}
                            >
                              <Visibility />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Update Status">
                            <IconButton 
                              size="small"
                              onClick={() => {
                                // Show status update dialog or handle status update
                                const newStatus = prompt('Enter new status (open/investigating/contained/resolved/closed):', incident.status);
                                if (newStatus && ['open', 'investigating', 'contained', 'resolved', 'closed'].includes(newStatus.toLowerCase())) {
                                  handleUpdateIncidentStatus(incident.id, newStatus.toLowerCase());
                                }
                              }}
                            >
                              <Assignment />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Download Report">
                              <IconButton 
                                size="small"
                              onClick={() => handleDownloadIncidentReport(incident)}
                              >
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

        {/* Response Workflows */}
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Active Workflows
            </Typography>
            <Box display="flex" flexDirection="column" gap={2}>
              {workflows.filter(w => w.status === 'in_progress').map((workflow) => (
                <Card key={workflow.id} variant="outlined">
                  <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
                    <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                      <Typography variant="body2" fontWeight="bold">
                        {workflow.step}
                      </Typography>
                      <Chip
                        icon={getWorkflowStatusIcon(workflow.status)}
                        label={workflow.status.replace('_', ' ').toUpperCase()}
                        color={getWorkflowStatusColor(workflow.status)}
                        size="small"
                      />
                    </Box>
                    <Typography variant="caption" color="textSecondary" display="block">
                      {workflow.description}
                      </Typography>
                    <Typography variant="caption" color="textSecondary" display="block" mt={1}>
                      Assignee: {workflow.assignee}
                      </Typography>
                    <Typography variant="caption" color="textSecondary" display="block">
                      Started: {new Date(workflow.startTime).toLocaleTimeString()}
                    </Typography>
                  </CardContent>
                </Card>
              ))}
            </Box>
          </Paper>
        </Grid>
      </Grid>

      {/* New Incident Dialog */}
      <Dialog open={openIncidentDialog} onClose={() => setOpenIncidentDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>New Incident</DialogTitle>
        <DialogContent>
          <Box display="flex" flexDirection="column" gap={2} mt={1}>
            <TextField
              label="Incident Title"
              value={incidentForm.title}
              onChange={(e) => setIncidentForm({ ...incidentForm, title: e.target.value })}
              fullWidth
            />
            <TextField
              label="Description"
              value={incidentForm.description}
              onChange={(e) => setIncidentForm({ ...incidentForm, description: e.target.value })}
              multiline
              rows={3}
              fullWidth
            />
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Severity</InputLabel>
                  <Select
                    value={incidentForm.severity}
                    onChange={(e) => setIncidentForm({ ...incidentForm, severity: e.target.value as any })}
                    label="Severity"
                  >
                    <MenuItem value="low">Low</MenuItem>
                    <MenuItem value="medium">Medium</MenuItem>
                    <MenuItem value="high">High</MenuItem>
                    <MenuItem value="critical">Critical</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Priority</InputLabel>
                  <Select
                    value={incidentForm.priority}
                    onChange={(e) => setIncidentForm({ ...incidentForm, priority: e.target.value as any })}
                    label="Priority"
                  >
                    <MenuItem value="low">Low</MenuItem>
                    <MenuItem value="medium">Medium</MenuItem>
                    <MenuItem value="high">High</MenuItem>
                    <MenuItem value="critical">Critical</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
                <TextField
              label="Assignee"
              value={incidentForm.assignee}
              onChange={(e) => setIncidentForm({ ...incidentForm, assignee: e.target.value })}
              fullWidth
            />
            <TextField
              label="Affected Systems (comma-separated)"
                  value={incidentForm.affectedSystems}
                  onChange={(e) => setIncidentForm({ ...incidentForm, affectedSystems: e.target.value })}
                  fullWidth
                />
                <TextField
              label="Indicators (comma-separated)"
              value={incidentForm.indicators}
              onChange={(e) => setIncidentForm({ ...incidentForm, indicators: e.target.value })}
                  fullWidth
                />
            <TextField
              label="Tags (comma-separated)"
              value={incidentForm.tags}
              onChange={(e) => setIncidentForm({ ...incidentForm, tags: e.target.value })}
              fullWidth
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenIncidentDialog(false)}>Cancel</Button>
          <Button onClick={handleIncidentSubmit} variant="contained">
            Create Incident
          </Button>
        </DialogActions>
      </Dialog>

      {/* Incident Details Dialog */}
      <Dialog 
        open={!!selectedIncident} 
        onClose={() => setSelectedIncident(null)} 
        maxWidth="lg" 
        fullWidth
      >
        {selectedIncident && (
          <>
            <DialogTitle>Incident Details: {selectedIncident.title}</DialogTitle>
            <DialogContent>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" gutterBottom>Incident Information</Typography>
                  <Box display="flex" flexDirection="column" gap={1}>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Status:</Typography>
                      <Chip
                        label={selectedIncident.status.toUpperCase()}
                        color={getStatusColor(selectedIncident.status)}
                        size="small"
                      />
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Severity:</Typography>
                      <Chip
                        icon={getSeverityIcon(selectedIncident.severity)}
                        label={selectedIncident.severity.toUpperCase()}
                        color={getSeverityColor(selectedIncident.severity)}
                        size="small"
                      />
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Assignee:</Typography>
                      <Typography variant="body2" fontWeight="bold">
                        {selectedIncident.assignee}
                      </Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Reporter:</Typography>
                      <Typography variant="body2" fontWeight="bold">
                        {selectedIncident.reporter}
                      </Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Created:</Typography>
                      <Typography variant="body2" fontWeight="bold">
                        {new Date(selectedIncident.createdAt).toLocaleString()}
                      </Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Updated:</Typography>
                      <Typography variant="body2" fontWeight="bold">
                        {new Date(selectedIncident.updatedAt).toLocaleString()}
                      </Typography>
                    </Box>
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" gutterBottom>SLA Information</Typography>
                  <Box display="flex" flexDirection="column" gap={1}>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Target:</Typography>
                        <Typography variant="body2" fontWeight="bold">
                        {selectedIncident.sla.target}
                        </Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Current:</Typography>
                      <Typography variant="body2" fontWeight="bold" color={selectedIncident.sla.breached ? 'error' : 'success'}>
                        {selectedIncident.sla.current}
                      </Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Breached:</Typography>
                      <Chip
                        label={selectedIncident.sla.breached ? 'YES' : 'NO'}
                        color={selectedIncident.sla.breached ? 'error' : 'success'}
                        size="small"
                      />
                    </Box>
                    </Box>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="h6" gutterBottom>Description</Typography>
                  <Typography variant="body2">
                    {selectedIncident.description}
                        </Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" gutterBottom>Affected Systems</Typography>
                  <Box display="flex" flexWrap="wrap" gap={1}>
                    {selectedIncident.affectedSystems.map((system, index) => (
                      <Chip key={index} label={system} size="small" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6" gutterBottom>Indicators</Typography>
                  <Box display="flex" flexWrap="wrap" gap={1}>
                    {selectedIncident.indicators.map((indicator, index) => (
                      <Chip key={index} label={indicator} size="small" color="warning" />
                    ))}
                  </Box>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="h6" gutterBottom>Tags</Typography>
                  <Box display="flex" flexWrap="wrap" gap={1}>
                    {selectedIncident.tags.map((tag, index) => (
                      <Chip key={index} label={tag} size="small" />
                    ))}
                  </Box>
                </Grid>
              </Grid>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setSelectedIncident(null)}>Close</Button>
              <Button variant="contained" startIcon={<Assignment />}>
                Update Status
                </Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  );
};

export default IncidentResponse; 