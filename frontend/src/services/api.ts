const API_BASE_URL = 'http://localhost:8000';

export interface ThreatPrediction {
  prediction: string;
  confidence: number;
  probabilities: Record<string, number>;
  threat_category: string;
  model_status: string;
  timestamp: string;
  input_data: any;
}

export interface MLTestResult {
  status: string;
  ml_components: {
    threat_classifier: {
      status: string;
      predictions: Array<{
        prediction: string;
        confidence: number;
        threat_category: string;
        timestamp: number;
      }>;
      model_info: {
        type: string;
        version: string;
        last_trained: string;
      };
    };
    anomaly_detector: {
      status: string;
      detections: Array<{
        type: string;
        confidence: number;
        severity: string;
      }>;
    };
    sequential_analyzer: {
      status: string;
      patterns_detected: number;
      lateral_movement_attempts: number;
    };
  };
  performance_metrics: {
    accuracy: number;
    precision: number;
    recall: number;
    f1_score: number;
    model_type: string;
    training_samples: number;
  };
  overall_status: string;
  timestamp: number;
  framework: string;
}

export interface DashboardData {
  security_metrics: {
    total_threats: number;
    active_incidents: number;
    blocked_attacks: number;
    system_health: number;
  };
  threat_trends: Array<{
    date: string;
    threats: number;
    incidents: number;
  }>;
  threat_distribution: Array<{
    category: string;
    count: number;
    percentage: number;
  }>;
}

export interface ThreatHuntingData {
  queries: Array<{
    id: string;
    query: string;
    status: string;
    results: number;
    timestamp: string;
  }>;
  ioc_analysis: Array<{
    indicator: string;
    type: string;
    confidence: number;
    threat_level: string;
  }>;
  behavioral_analysis: Array<{
    user_id: string;
    behavior_score: number;
    anomaly_detected: boolean;
    risk_level: string;
  }>;
}

export interface IncidentResponseData {
  incidents: Array<{
    id: string;
    title: string;
    severity: string;
    status: string;
    timestamp: string;
    description: string;
  }>;
  response_actions: Array<{
    id: string;
    action: string;
    status: string;
    effectiveness: number;
    timestamp: string;
  }>;
  soar_integration: {
    status: string;
    connected_systems: string[];
    automation_level: string;
  };
}

export interface AccessControlData {
  risk_assessments: Array<{
    id: string;
    user_id: string;
    risk_score: number;
    access_decision: string;
    timestamp: string;
    factors: string[];
  }>;
  user_behaviors: Array<{
    user_id: string;
    session_duration: number;
    access_patterns: string[];
    risk_level: string;
  }>;
}

// API Service Class
class APIService {
  private baseURL: string;

  constructor(baseURL: string = API_BASE_URL) {
    this.baseURL = baseURL;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseURL}${endpoint}`;
    const response = await fetch(url, {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    });

    if (!response.ok) {
      throw new Error(`API request failed: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  // Health Check
  async healthCheck(): Promise<{ status: string; approach: string }> {
    return this.request('/health');
  }

  // ML Test
  async testML(): Promise<MLTestResult> {
    return this.request('/api/test-ml', {
      method: 'POST',
      body: JSON.stringify({}),
    });
  }

  // Threat Prediction
  async predictThreat(networkData: any): Promise<ThreatPrediction> {
    return this.request('/api/predict-threat-simple', {
      method: 'POST',
      body: JSON.stringify({ network_data: networkData }),
    });
  }

  // Framework Info
  async getFrameworkInfo(): Promise<any> {
    return this.request('/api/framework-info');
  }

  // Dashboard Data
  async getDashboardData(): Promise<DashboardData> {
    return this.request('/api/v1/dynamic/dashboard');
  }

  // Threats Data
  async getThreats(limit: number = 50): Promise<{ threats: any[] }> {
    return this.request(`/api/v1/dynamic/threats?limit=${limit}`);
  }

  // Incidents Data
  async getIncidents(limit: number = 20): Promise<{ incidents: any[] }> {
    return this.request(`/api/v1/dynamic/incidents?limit=${limit}`);
  }

  // System Status
  async getSystemStatus(): Promise<any> {
    return this.request('/api/v1/dynamic/system-status');
  }

  // Start Real-time Service
  async startRealtimeService(): Promise<{ message: string }> {
    return this.request('/api/v1/dynamic/start-realtime', {
      method: 'POST',
    });
  }

  // Stop Real-time Service
  async stopRealtimeService(): Promise<{ message: string }> {
    return this.request('/api/v1/dynamic/stop-realtime', {
      method: 'POST',
    });
  }

  // Hybrid Approach Info
  async getHybridApproachInfo(): Promise<any> {
    return this.request('/api/v1/dynamic/hybrid-approach-info');
  }

  // Access Control Methods
  async getAccessControlData(): Promise<any> {
    try {
      // Try to get real access control data from backend
      const response = await this.request('/api/v1/access-control/data');
      return response;
    } catch (error) {
      console.warn('Access control API not available, using fallback data');
      // Return fallback data structure
      return {
        riskAssessments: [
          {
            id: '1',
            userId: 'user1',
            username: 'john.doe',
            tpsScore: 85.5,
            riskFactors: ['Unusual login time', 'Unknown device', 'High-risk location'],
            accessDecision: 'mfa',
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
            accessDecision: 'allow',
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
            accessDecision: 'block',
            isAnomalous: true,
            anomalyScore: 0.92,
            timestamp: new Date(Date.now() - 600000).toISOString(),
            deviceInfo: 'Unknown device',
            networkType: 'public_wifi',
            ipAddress: '203.45.67.89',
          }
        ],
        userBehaviors: [
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
        ]
      };
    }
  }
}

// Export singleton instance
export const apiService = new APIService();

// Export default for backward compatibility
export default apiService; 