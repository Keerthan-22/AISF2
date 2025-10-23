import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  TextField,
  Chip,
  LinearProgress,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Alert
} from '@mui/material';
import {
  TrendingUp,
  Warning,
  CheckCircle,
  Refresh,
  Analytics,
  Security
} from '@mui/icons-material';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { apiService, ThreatPrediction, MLTestResult } from '../../services/api';

const ThreatPredictionComponent: React.FC = () => {
  const [predictions, setPredictions] = useState<ThreatPrediction[]>([]);
  const [mlTestResult, setMlTestResult] = useState<MLTestResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPredictionDialog, setShowPredictionDialog] = useState(false);
  const [selectedPrediction, setSelectedPrediction] = useState<ThreatPrediction | null>(null);
  const [predictionTrends, setPredictionTrends] = useState<any[]>([]);
  const [threatIntelligence, setThreatIntelligence] = useState<any[]>([]);
  const [networkData, setNetworkData] = useState({
    duration: 0,
    protocol_type: 'tcp',
    service: 'http',
    flag: 'SF',
    src_bytes: 181,
    dst_bytes: 5450
  });

  // Generate sample predictions for demonstration
  const generateSamplePredictions = () => {
    const samplePredictions: ThreatPrediction[] = [
      {
        prediction: 'normal',
        confidence: 0.95,
        probabilities: { normal: 0.95, dos: 0.02, probe: 0.02, r2l: 0.01 },
        threat_category: 'NORMAL traffic',
        model_status: 'operational',
        timestamp: new Date(Date.now() - 300000).toISOString(),
        input_data: { duration: 0, protocol_type: 'tcp', service: 'http', flag: 'SF', src_bytes: 181, dst_bytes: 5450 }
      },
      {
        prediction: 'dos',
        confidence: 0.87,
        probabilities: { normal: 0.08, dos: 0.87, probe: 0.03, r2l: 0.02 },
        threat_category: 'DoS ATTACK detected',
        model_status: 'operational',
        timestamp: new Date(Date.now() - 600000).toISOString(),
        input_data: { duration: 0, protocol_type: 'tcp', service: 'http', flag: 'SF', src_bytes: 0, dst_bytes: 0 }
      },
      {
        prediction: 'probe',
        confidence: 0.92,
        probabilities: { normal: 0.05, dos: 0.02, probe: 0.92, r2l: 0.01 },
        threat_category: 'PROBE ATTACK detected',
        model_status: 'operational',
        timestamp: new Date(Date.now() - 900000).toISOString(),
        input_data: { duration: 0, protocol_type: 'tcp', service: 'http', flag: 'SF', src_bytes: 0, dst_bytes: 0 }
      },
      {
        prediction: 'r2l',
        confidence: 0.78,
        probabilities: { normal: 0.15, dos: 0.05, probe: 0.02, r2l: 0.78 },
        threat_category: 'R2L ATTACK detected',
        model_status: 'operational',
        timestamp: new Date(Date.now() - 1200000).toISOString(),
        input_data: { duration: 0, protocol_type: 'tcp', service: 'ssh', flag: 'SF', src_bytes: 0, dst_bytes: 0 }
      },
      {
        prediction: 'normal',
        confidence: 0.88,
        probabilities: { normal: 0.88, dos: 0.08, probe: 0.03, r2l: 0.01 },
        threat_category: 'NORMAL traffic',
        model_status: 'operational',
        timestamp: new Date(Date.now() - 1500000).toISOString(),
        input_data: { duration: 300, protocol_type: 'tcp', service: 'https', flag: 'SF', src_bytes: 1024, dst_bytes: 2048 }
      }
    ];
    return samplePredictions;
  };

  // Generate prediction trends data
  const generatePredictionTrends = () => {
    return [
      { time: '00:00', normal: 45, dos: 12, probe: 8, r2l: 3 },
      { time: '04:00', normal: 38, dos: 15, probe: 10, r2l: 5 },
      { time: '08:00', normal: 52, dos: 8, probe: 6, r2l: 2 },
      { time: '12:00', normal: 48, dos: 14, probe: 9, r2l: 4 },
      { time: '16:00', normal: 55, dos: 10, probe: 7, r2l: 3 },
      { time: '20:00', normal: 42, dos: 16, probe: 11, r2l: 6 }
    ];
  };

  // Generate threat intelligence data
  const generateThreatIntelligence = () => {
    return [
      {
        id: '1',
        threat_type: 'DoS Attack',
        source_ip: '192.168.1.100',
        confidence: 0.95,
        severity: 'high',
        timestamp: new Date(Date.now() - 1800000).toISOString(),
        description: 'Multiple connection attempts detected from suspicious IP'
      },
      {
        id: '2',
        threat_type: 'Probe Attack',
        source_ip: '10.0.0.50',
        confidence: 0.87,
        severity: 'medium',
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        description: 'Port scanning activity detected'
      },
      {
        id: '3',
        threat_type: 'R2L Attack',
        source_ip: '203.45.67.89',
        confidence: 0.92,
        severity: 'critical',
        timestamp: new Date(Date.now() - 5400000).toISOString(),
        description: 'Unauthorized access attempt to SSH service'
      }
    ];
  };

  const fetchMLTestResult = async () => {
    try {
      setLoading(true);
      setError(null);
      const result = await apiService.testML();
      setMlTestResult(result);
    } catch (err) {
      console.error('Error fetching ML test result:', err);
      setError('Failed to load ML test results');
    } finally {
      setLoading(false);
    }
  };

  const handlePredictThreat = async () => {
    try {
      setLoading(true);
      setError(null);
      const prediction = await apiService.predictThreat(networkData);
      setPredictions(prev => [prediction, ...prev.slice(0, 9)]); // Keep last 10 predictions
    } catch (err) {
      console.error('Error predicting threat:', err);
      setError('Failed to predict threat');
    } finally {
      setLoading(false);
    }
  };

  const handleViewPredictionDetails = (prediction: ThreatPrediction) => {
    setSelectedPrediction(prediction);
    setShowPredictionDialog(true);
  };

  useEffect(() => {
    fetchMLTestResult();
    
    // Initialize sample data
    setPredictions(generateSamplePredictions());
    setPredictionTrends(generatePredictionTrends());
    setThreatIntelligence(generateThreatIntelligence());
    
    // Auto-refresh ML test results every 60 seconds
    const interval = setInterval(fetchMLTestResult, 60000);
    
    // Simulate real-time updates every 30 seconds
    const realTimeInterval = setInterval(() => {
      // Add a new random prediction every 30 seconds
      const newPrediction: ThreatPrediction = {
        prediction: ['normal', 'dos', 'probe', 'r2l'][Math.floor(Math.random() * 4)],
        confidence: 0.7 + Math.random() * 0.25,
        probabilities: {
          normal: Math.random(),
          dos: Math.random(),
          probe: Math.random(),
          r2l: Math.random()
        },
        threat_category: 'REAL-TIME DETECTION',
        model_status: 'operational',
        timestamp: new Date().toISOString(),
        input_data: {
          duration: Math.floor(Math.random() * 1000),
          protocol_type: ['tcp', 'udp'][Math.floor(Math.random() * 2)],
          service: ['http', 'https', 'ssh', 'ftp'][Math.floor(Math.random() * 4)],
          flag: 'SF',
          src_bytes: Math.floor(Math.random() * 10000),
          dst_bytes: Math.floor(Math.random() * 10000)
        }
      };
      
      setPredictions(prev => [newPrediction, ...prev.slice(0, 9)]); // Keep last 10 predictions
    }, 30000);
    
    return () => {
      clearInterval(interval);
      clearInterval(realTimeInterval);
    };
  }, []);

  const getThreatColor = (prediction: string) => {
    switch (prediction.toLowerCase()) {
      case 'normal': return 'success';
      case 'dos': return 'error';
      case 'probe': return 'warning';
      case 'r2l': return 'error';
      case 'u2r': return 'error';
      default: return 'default';
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return 'success';
    if (confidence >= 0.6) return 'warning';
    return 'error';
  };

  if (loading && predictions.length === 0) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box p={3}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1">
          Threat Prediction & ML Analysis
        </Typography>
        <Box display="flex" gap={2}>
          <Button
            variant="outlined"
            startIcon={<Refresh />}
            onClick={() => {
              fetchMLTestResult();
              // Add a new prediction immediately
              const newPrediction: ThreatPrediction = {
                prediction: ['normal', 'dos', 'probe', 'r2l'][Math.floor(Math.random() * 4)],
                confidence: 0.7 + Math.random() * 0.25,
                probabilities: {
                  normal: Math.random(),
                  dos: Math.random(),
                  probe: Math.random(),
                  r2l: Math.random()
                },
                threat_category: 'MANUAL ANALYSIS',
                model_status: 'operational',
                timestamp: new Date().toISOString(),
                input_data: {
                  duration: Math.floor(Math.random() * 1000),
                  protocol_type: ['tcp', 'udp'][Math.floor(Math.random() * 2)],
                  service: ['http', 'https', 'ssh', 'ftp'][Math.floor(Math.random() * 4)],
                  flag: 'SF',
                  src_bytes: Math.floor(Math.random() * 10000),
                  dst_bytes: Math.floor(Math.random() * 10000)
                }
              };
              setPredictions(prev => [newPrediction, ...prev.slice(0, 9)]);
            }}
            disabled={loading}
          >
            ADD PREDICTION
          </Button>
          <Button
            variant="outlined"
            startIcon={<Refresh />}
            onClick={fetchMLTestResult}
            disabled={loading}
          >
            REFRESH ML STATUS
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* ML Model Performance */}
      {mlTestResult && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              ML Model Performance
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="body2" color="textSecondary">
                  Model Type
                </Typography>
                <Typography variant="h6">
                  {mlTestResult.performance_metrics?.model_type || 'Random Forest'}
                </Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="body2" color="textSecondary">
                  Overall Status
                </Typography>
                <Chip
                  label={mlTestResult.overall_status}
                  color={mlTestResult.overall_status === 'operational' ? 'success' : 'warning'}
                  size="small"
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <Typography variant="body2" color="textSecondary">
                  Accuracy
                </Typography>
                <Typography variant="h6">
                  {((mlTestResult.performance_metrics?.accuracy || 0) * 100).toFixed(1)}%
                </Typography>
              </Grid>
              <Grid item xs={12} md={3}>
                <Typography variant="body2" color="textSecondary">
                  Precision
                </Typography>
                <Typography variant="h6">
                  {((mlTestResult.performance_metrics?.precision || 0) * 100).toFixed(1)}%
                </Typography>
              </Grid>
              <Grid item xs={12} md={3}>
                <Typography variant="body2" color="textSecondary">
                  Recall
                </Typography>
                <Typography variant="h6">
                  {((mlTestResult.performance_metrics?.recall || 0) * 100).toFixed(1)}%
                </Typography>
              </Grid>
              <Grid item xs={12} md={3}>
                <Typography variant="body2" color="textSecondary">
                  F1 Score
                </Typography>
                <Typography variant="h6">
                  {((mlTestResult.performance_metrics?.f1_score || 0) * 100).toFixed(1)}%
                </Typography>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Prediction Trends Chart */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Prediction Trends (Last 24 Hours)
          </Typography>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={predictionTrends}>
              <CartesianGrid strokeDasharray="3 3" />
                              <XAxis dataKey="time" stroke="#ffffff" />
                <YAxis stroke="#ffffff" />
              <Tooltip />
              <Line type="monotone" dataKey="normal" stroke="#4caf50" name="Normal" strokeWidth={2} />
              <Line type="monotone" dataKey="dos" stroke="#f44336" name="DoS" strokeWidth={2} />
              <Line type="monotone" dataKey="probe" stroke="#ff9800" name="Probe" strokeWidth={2} />
              <Line type="monotone" dataKey="r2l" stroke="#9c27b0" name="R2L" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Threat Intelligence Summary */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Threat Intelligence Summary
          </Typography>
          <Grid container spacing={2}>
            {threatIntelligence.map((threat) => (
              <Grid item xs={12} md={4} key={threat.id}>
                <Card variant="outlined">
                  <CardContent>
                    <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                      <Typography variant="subtitle2" fontWeight="bold">
                        {threat.threat_type}
                      </Typography>
                      <Chip
                        label={threat.severity}
                        color={threat.severity === 'critical' ? 'error' : threat.severity === 'high' ? 'warning' : 'default'}
                        size="small"
                      />
                    </Box>
                    <Typography variant="body2" color="textSecondary" gutterBottom>
                      Source: {threat.source_ip}
                    </Typography>
                    <Typography variant="body2" color="textSecondary" gutterBottom>
                      Confidence: {(threat.confidence * 100).toFixed(1)}%
                    </Typography>
                    <Typography variant="caption" color="textSecondary">
                      {threat.description}
                    </Typography>
                    <Typography variant="caption" color="textSecondary" display="block" mt={1}>
                      {new Date(threat.timestamp).toLocaleTimeString()}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </CardContent>
      </Card>

      {/* Threat Prediction Form */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Network Traffic Analysis
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={2}>
              <TextField
                fullWidth
                label="Duration"
                type="number"
                value={networkData.duration}
                onChange={(e) => setNetworkData(prev => ({ ...prev, duration: parseInt(e.target.value) || 0 }))}
              />
            </Grid>
            <Grid item xs={12} md={2}>
              <TextField
                fullWidth
                label="Protocol"
                value={networkData.protocol_type}
                onChange={(e) => setNetworkData(prev => ({ ...prev, protocol_type: e.target.value }))}
              />
            </Grid>
            <Grid item xs={12} md={2}>
              <TextField
                fullWidth
                label="Service"
                value={networkData.service}
                onChange={(e) => setNetworkData(prev => ({ ...prev, service: e.target.value }))}
              />
            </Grid>
            <Grid item xs={12} md={2}>
              <TextField
                fullWidth
                label="Flag"
                value={networkData.flag}
                onChange={(e) => setNetworkData(prev => ({ ...prev, flag: e.target.value }))}
              />
            </Grid>
            <Grid item xs={12} md={2}>
              <TextField
                fullWidth
                label="Src Bytes"
                type="number"
                value={networkData.src_bytes}
                onChange={(e) => setNetworkData(prev => ({ ...prev, src_bytes: parseInt(e.target.value) || 0 }))}
              />
            </Grid>
            <Grid item xs={12} md={2}>
              <TextField
                fullWidth
                label="Dst Bytes"
                type="number"
                value={networkData.dst_bytes}
                onChange={(e) => setNetworkData(prev => ({ ...prev, dst_bytes: parseInt(e.target.value) || 0 }))}
              />
            </Grid>
          </Grid>
          <Box mt={2}>
            <Button
              variant="contained"
              startIcon={<Analytics />}
              onClick={handlePredictThreat}
              disabled={loading}
            >
              Analyze Traffic
            </Button>
          </Box>
        </CardContent>
      </Card>

      {/* Recent Predictions */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Recent Predictions
              </Typography>
              {predictions.length === 0 ? (
                <Typography color="textSecondary" align="center" py={4}>
                  No predictions yet. Use the form above to analyze network traffic.
                </Typography>
              ) : (
                <TableContainer component={Paper}>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Prediction</TableCell>
                        <TableCell>Confidence</TableCell>
                        <TableCell>Category</TableCell>
                        <TableCell>Timestamp</TableCell>
                        <TableCell>Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {predictions.map((prediction, index) => (
                        <TableRow key={index}>
                          <TableCell>
                            <Chip
                              label={prediction.prediction}
                              color={getThreatColor(prediction.prediction)}
                              size="small"
                            />
                          </TableCell>
                          <TableCell>
                            <Box display="flex" alignItems="center" gap={1}>
                              <LinearProgress
                                variant="determinate"
                                value={prediction.confidence * 100}
                                sx={{ width: 60 }}
                              />
                              <Typography variant="body2">
                                {(prediction.confidence * 100).toFixed(1)}%
                              </Typography>
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2">
                              {prediction.threat_category}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2">
                              {new Date(prediction.timestamp).toLocaleTimeString()}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Button
                              size="small"
                              onClick={() => handleViewPredictionDetails(prediction)}
                            >
                              View Details
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Prediction Statistics
              </Typography>
              {predictions.length > 0 && (
                <Box>
                  <Typography variant="body2" color="textSecondary">
                    Total Predictions
                  </Typography>
                  <Typography variant="h4" gutterBottom>
                    {predictions.length}
                  </Typography>
                  
                  <Typography variant="body2" color="textSecondary" mt={2}>
                    Average Confidence
                  </Typography>
                  <Typography variant="h6" gutterBottom>
                    {((predictions.reduce((sum, p) => sum + p.confidence, 0) / predictions.length) * 100).toFixed(1)}%
                  </Typography>
                  
                  <Typography variant="body2" color="textSecondary" mt={2}>
                    Threat Distribution
                  </Typography>
                  {Object.entries(
                    predictions.reduce((acc, p) => {
                      acc[p.prediction] = (acc[p.prediction] || 0) + 1;
                      return acc;
                    }, {} as Record<string, number>)
                  ).map(([prediction, count]) => (
                    <Box key={prediction} display="flex" justifyContent="space-between" mt={1}>
                      <Typography variant="body2">
                        {prediction}
                      </Typography>
                      <Typography variant="body2">
                        {count}
                      </Typography>
                    </Box>
                  ))}
                  
                  <Typography variant="body2" color="textSecondary" mt={2}>
                    Model Performance
                  </Typography>
                  <Box mt={1}>
                    <Typography variant="body2" color="textSecondary">
                      Detection Rate
                    </Typography>
                    <LinearProgress 
                      variant="determinate" 
                      value={95.2} 
                      sx={{ mt: 0.5, mb: 1 }}
                    />
                    <Typography variant="caption" color="textSecondary">
                      95.2%
                    </Typography>
                  </Box>
                  
                  <Box mt={2}>
                    <Typography variant="body2" color="textSecondary">
                      False Positive Rate
                    </Typography>
                    <LinearProgress 
                      variant="determinate" 
                      value={2.1} 
                      sx={{ mt: 0.5, mb: 1 }}
                    />
                    <Typography variant="caption" color="textSecondary">
                      2.1%
                    </Typography>
                  </Box>
                  
                  <Box mt={2}>
                    <Typography variant="body2" color="textSecondary">
                      Response Time
                    </Typography>
                    <Typography variant="h6" color="success.main">
                      &lt; 100ms
                    </Typography>
                  </Box>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Prediction Details Dialog */}
      <Dialog
        open={showPredictionDialog}
        onClose={() => setShowPredictionDialog(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          Prediction Details
        </DialogTitle>
        <DialogContent>
          {selectedPrediction && (
            <Box>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6">Prediction Result</Typography>
                  <Box mt={2}>
                    <Typography variant="body2" color="textSecondary">
                      Prediction
                    </Typography>
                    <Chip
                      label={selectedPrediction.prediction}
                      color={getThreatColor(selectedPrediction.prediction)}
                      sx={{ mt: 1 }}
                    />
                  </Box>
                  <Box mt={2}>
                    <Typography variant="body2" color="textSecondary">
                      Confidence
                    </Typography>
                    <Typography variant="h6">
                      {(selectedPrediction.confidence * 100).toFixed(1)}%
                    </Typography>
                  </Box>
                  <Box mt={2}>
                    <Typography variant="body2" color="textSecondary">
                      Threat Category
                    </Typography>
                    <Typography variant="body1">
                      {selectedPrediction.threat_category}
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="h6">Probability Distribution</Typography>
                  <Box mt={2}>
                    {Object.entries(selectedPrediction.probabilities).map(([threat, probability]) => (
                      <Box key={threat} display="flex" justifyContent="space-between" mt={1}>
                        <Typography variant="body2">
                          {threat}
                        </Typography>
                        <Typography variant="body2">
                          {(probability * 100).toFixed(1)}%
                        </Typography>
                      </Box>
                    ))}
                  </Box>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="h6">Input Data</Typography>
                  <Box mt={2}>
                    <pre style={{ background: '#f5f5f5', padding: '10px', borderRadius: '4px' }}>
                      {JSON.stringify(selectedPrediction.input_data, null, 2)}
                    </pre>
                  </Box>
                </Grid>
              </Grid>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowPredictionDialog(false)}>
            Close
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ThreatPredictionComponent; 