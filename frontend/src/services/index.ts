// AISF API Service Layer

import axios, { AxiosInstance, AxiosResponse } from 'axios';
import {
  User,
  RiskAssessmentResponse,
  RiskAssessmentRequest,
  ThreatPredictionResponse,
  ThreatIntelligence,
  ComprehensiveHuntingResult,
  IncidentResponseResponse,
  AccessControlStats,
  ThreatPredictionStats,
  ThreatHuntingStats,
  IncidentResponseStats,
  SOARStatus,
  ModelPerformance,
  ApiResponse,
  PaginatedResponse
} from '../types';

// API Configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api';

// Create axios instance with default configuration
const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response: AxiosResponse) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized access
      localStorage.removeItem('auth_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Authentication Services
export const authService = {
  login: async (username: string, password: string): Promise<{ access_token: string; user: User }> => {
    const response = await apiClient.post('/auth/login', { username, password });
    return response.data;
  },

  logout: async (): Promise<void> => {
    await apiClient.post('/auth/logout');
    localStorage.removeItem('auth_token');
  },

  refreshToken: async (): Promise<{ access_token: string }> => {
    const response = await apiClient.post('/auth/refresh');
    return response.data;
  },

  getCurrentUser: async (): Promise<User> => {
    const response = await apiClient.get('/auth/me');
    return response.data;
  },
};

// Access Control Services
export const accessControlService = {
  assessRisk: async (request: RiskAssessmentRequest): Promise<RiskAssessmentResponse> => {
    const response = await apiClient.post('/access-control/assess-risk', request);
    return response.data;
  },

  updateUserBehavior: async (behaviorData: any[]): Promise<{ message: string; data_points: number }> => {
    const response = await apiClient.post('/access-control/user-behavior', { behavior_data: behaviorData });
    return response.data;
  },

  getRiskHistory: async (userId: number, limit: number = 50): Promise<{ user_id: number; assessments: any[] }> => {
    const response = await apiClient.get(`/access-control/risk-history/${userId}?limit=${limit}`);
    return response.data;
  },

  getCurrentRisk: async (userId: number): Promise<{ user_id: number; current_risk: any }> => {
    const response = await apiClient.get(`/access-control/current-risk/${userId}`);
    return response.data;
  },

  makeManualDecision: async (userId: number, decision: string, reason: string): Promise<any> => {
    const response = await apiClient.post('/access-control/manual-decision', {
      user_id: userId,
      decision,
      reason
    });
    return response.data;
  },

  getStats: async (): Promise<AccessControlStats> => {
    const response = await apiClient.get('/access-control/stats');
    return response.data;
  },
};

// Threat Prediction Services
export const threatPredictionService = {
  predictThreat: async (networkData: any): Promise<ThreatPredictionResponse> => {
    const response = await apiClient.post('/threat-prediction/predict-threat', {
      network_data: networkData,
      source: 'network_monitor'
    });
    return response.data;
  },

  enrichThreatIntelligence: async (threatData: any): Promise<ThreatIntelligence> => {
    const response = await apiClient.post('/threat-prediction/threat-intelligence', {
      threat_data: threatData,
      include_external_feeds: true,
      include_behavioral_analysis: true
    });
    return response.data;
  },

  detectZeroDay: async (networkData: any, threshold?: number): Promise<any> => {
    const response = await apiClient.post('/threat-prediction/zero-day-detection', {
      network_data: networkData,
      threshold
    });
    return response.data;
  },

  getModelPerformance: async (): Promise<{ models: Record<string, ModelPerformance>; overall_performance: any }> => {
    const response = await apiClient.get('/threat-prediction/model-performance');
    return response.data;
  },

  getThreatHistory: async (limit: number = 50, threatType?: string, minConfidence?: number): Promise<any> => {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    if (threatType) params.append('threat_type', threatType);
    if (minConfidence) params.append('min_confidence', minConfidence.toString());

    const response = await apiClient.get(`/threat-prediction/threat-history?${params.toString()}`);
    return response.data;
  },

  getThreatDetails: async (threatId: number): Promise<any> => {
    const response = await apiClient.get(`/threat-prediction/threat/${threatId}`);
    return response.data;
  },

  retrainModels: async (): Promise<any> => {
    const response = await apiClient.post('/threat-prediction/retrain-models');
    return response.data;
  },

  getPredictionStats: async (): Promise<ThreatPredictionStats> => {
    const response = await apiClient.get('/threat-prediction/prediction-stats');
    return response.data;
  },
};

// Threat Hunting Services
export const threatHuntingService = {
  huntThreats: async (dataSource: string, queryType: string, filters: any = {}): Promise<any> => {
    const response = await apiClient.post('/threat-hunting/hunt-threats', {
      data_source: dataSource,
      query_type: queryType,
      filters
    });
    return response.data;
  },

  analyzeIocs: async (iocData: string): Promise<any> => {
    const response = await apiClient.post('/threat-hunting/ioc-analysis', {
      ioc_data: iocData,
      include_reputation_check: true
    });
    return response.data;
  },

  analyzeBehavior: async (userActivity: any, userId?: number): Promise<any> => {
    const response = await apiClient.post('/threat-hunting/behavioral-analysis', {
      user_activity: userActivity,
      user_id: userId
    });
    return response.data;
  },

  comprehensiveHunt: async (huntingData: any): Promise<ComprehensiveHuntingResult> => {
    const response = await apiClient.post('/threat-hunting/comprehensive-hunt', huntingData);
    return response.data;
  },

  getAvailableQueries: async (): Promise<any> => {
    const response = await apiClient.get('/threat-hunting/hunting-queries');
    return response.data;
  },

  getIocPatterns: async (): Promise<any> => {
    const response = await apiClient.get('/threat-hunting/ioc-patterns');
    return response.data;
  },

  getHuntingHistory: async (limit: number = 50, queryType?: string, minScore?: number): Promise<any> => {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    if (queryType) params.append('query_type', queryType);
    if (minScore) params.append('min_score', minScore.toString());

    const response = await apiClient.get(`/threat-hunting/hunting-history?${params.toString()}`);
    return response.data;
  },

  getHuntingStats: async (): Promise<ThreatHuntingStats> => {
    const response = await apiClient.get('/threat-hunting/hunting-stats');
    return response.data;
  },

  executeCustomQuery: async (queryData: any): Promise<any> => {
    const response = await apiClient.post('/threat-hunting/custom-query', queryData);
    return response.data;
  },
};

// Incident Response Services
export const incidentResponseService = {
  handleIncident: async (incidentData: any, threatData: any): Promise<IncidentResponseResponse> => {
    const response = await apiClient.post('/incident-response/handle-incident', {
      incident_data: incidentData,
      threat_data: threatData
    });
    return response.data;
  },

  selectResponse: async (incidentData: any, threatData: any, includeExecution: boolean = true): Promise<any> => {
    const response = await apiClient.post('/incident-response/select-response', {
      incident_data: incidentData,
      threat_data: threatData,
      include_execution: includeExecution
    });
    return response.data;
  },

  executeResponse: async (actions: any[], incidentData: any): Promise<any> => {
    const response = await apiClient.post('/incident-response/execute-response', {
      actions,
      incident_data: incidentData
    });
    return response.data;
  },

  getSoarStatus: async (): Promise<SOARStatus> => {
    const response = await apiClient.get('/incident-response/soar-integration');
    return response.data;
  },

  getAvailableActions: async (): Promise<any> => {
    const response = await apiClient.get('/incident-response/response-actions');
    return response.data;
  },

  getIncidentHistory: async (limit: number = 50, severity?: string, status?: string): Promise<any> => {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    if (severity) params.append('severity', severity);
    if (status) params.append('status', status);

    const response = await apiClient.get(`/incident-response/incident-history?${params.toString()}`);
    return response.data;
  },

  getIncidentDetails: async (incidentId: number): Promise<any> => {
    const response = await apiClient.get(`/incident-response/incident/${incidentId}`);
    return response.data;
  },

  updateIncidentStatus: async (incidentId: number, status: string): Promise<any> => {
    const response = await apiClient.put(`/incident-response/incident/${incidentId}/status?status=${status}`);
    return response.data;
  },

  getResponseStats: async (): Promise<IncidentResponseStats> => {
    const response = await apiClient.get('/incident-response/response-stats');
    return response.data;
  },

  testResponse: async (testData: any): Promise<any> => {
    const response = await apiClient.post('/incident-response/test-response', testData);
    return response.data;
  },

  updatePolicy: async (feedbackData: any): Promise<any> => {
    const response = await apiClient.post('/incident-response/update-policy', feedbackData);
    return response.data;
  },
};

// WebSocket Service
export class WebSocketService {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectInterval = 3000;

  constructor(private url: string, private onMessage: (data: any) => void) {}

  connect(): void {
    try {
      this.ws = new WebSocket(this.url);
      
      this.ws.onopen = () => {
        console.log('WebSocket connected');
        this.reconnectAttempts = 0;
      };

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this.onMessage(data);
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      };

      this.ws.onclose = () => {
        console.log('WebSocket disconnected');
        this.attemptReconnect();
      };

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
      };
    } catch (error) {
      console.error('Error creating WebSocket connection:', error);
    }
  }

  private attemptReconnect(): void {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);
      
      setTimeout(() => {
        this.connect();
      }, this.reconnectInterval * this.reconnectAttempts);
    } else {
      console.error('Max reconnection attempts reached');
    }
  }

  disconnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  sendMessage(message: any): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      console.warn('WebSocket is not connected');
    }
  }
}

// Utility functions
export const apiUtils = {
  handleError: (error: any): string => {
    if (error.response?.data?.detail) {
      return error.response.data.detail;
    } else if (error.message) {
      return error.message;
    } else {
      return 'An unexpected error occurred';
    }
  },

  formatDate: (dateString: string): string => {
    return new Date(dateString).toLocaleString();
  },

  formatBytes: (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  },

  getSeverityColor: (severity: string): string => {
    switch (severity.toLowerCase()) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f57c00';
      case 'medium': return '#fbc02d';
      case 'low': return '#388e3c';
      default: return '#757575';
    }
  },

  getStatusColor: (status: string): string => {
    switch (status.toLowerCase()) {
      case 'success': return '#388e3c';
      case 'warning': return '#f57c00';
      case 'error': return '#d32f2f';
      case 'info': return '#1976d2';
      default: return '#757575';
    }
  },
};

export default {
  auth: authService,
  accessControl: accessControlService,
  threatPrediction: threatPredictionService,
  threatHunting: threatHuntingService,
  incidentResponse: incidentResponseService,
  utils: apiUtils,
}; 