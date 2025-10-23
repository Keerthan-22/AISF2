// AISF Application Types

// User and Authentication
export interface User {
  id: number;
  username: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer';
  created_at: string;
  last_login?: string;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  loading: boolean;
}

// Access Control Types
export interface RiskFactor {
  login_time: number;
  device_status: number;
  network_type: number;
  ip_reputation: number;
  behavioral_pattern: number;
  failed_attempts: number;
  behavioral_anomaly?: number;
}

export interface RiskAssessment {
  id: number;
  user_id: number;
  tps_score: number;
  factors: string; // JSON string
  action_taken: 'allow' | 'mfa' | 'block' | 'lockout';
  timestamp: string;
}

export interface RiskAssessmentResponse {
  user_id: number;
  tps_score: number;
  risk_factors: RiskFactor;
  access_decision: 'allow' | 'mfa' | 'block' | 'lockout';
  is_anomalous: boolean;
  anomaly_score: number;
  timestamp: string;
}

export interface DeviceInfo {
  type: 'desktop' | 'laptop' | 'mobile' | 'tablet' | 'unknown';
  is_known_device: boolean;
  has_security_software: boolean;
}

export interface RiskAssessmentRequest {
  context: Record<string, any>;
  device_info: DeviceInfo;
  network_type: string;
  ip_address: string;
}

// Threat Prediction Types
export interface NetworkData {
  duration: number;
  src_bytes: number;
  dst_bytes: number;
  count: number;
  srv_count: number;
  serror_rate: number;
  srv_serror_rate: number;
  rerror_rate: number;
  srv_rerror_rate: number;
  same_srv_rate: number;
  diff_srv_rate: number;
  srv_diff_host_rate: number;
  dst_host_count: number;
  dst_host_srv_count: number;
  dst_host_same_srv_rate: number;
  dst_host_diff_srv_rate: number;
  dst_host_same_src_port_rate: number;
  dst_host_srv_diff_host_rate: number;
  dst_host_serror_rate: number;
  dst_host_srv_serror_rate: number;
  dst_host_rerror_rate: number;
  dst_host_srv_rerror_rate: number;
}

export interface ThreatPrediction {
  threat_type: 'normal' | 'dos' | 'probe' | 'r2l' | 'u2r' | 'malware' | 'phishing';
  confidence: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  model_used: string;
  features_analyzed: number;
  timestamp: string;
}

export interface ZeroDayDetection {
  is_zero_day: boolean;
  anomaly_score: number;
  confidence: number;
  detection_method: 'autoencoder' | 'statistical';
  timestamp: string;
}

export interface ThreatIntelligenceIndicator {
  source: 'internal_ml' | 'external_feeds' | 'behavioral_analysis' | 'historical_patterns';
  confidence: number;
  frequency: number;
  description?: string;
}

export interface ThreatIntelligence {
  enriched_data: any;
  intelligence_sources: number;
  overall_confidence: number;
  timestamp: string;
}

export interface ThreatPredictionResponse {
  threat_id: number;
  prediction: ThreatPrediction;
  zero_day_detection: ZeroDayDetection;
  overall_confidence: number;
  timestamp: string;
}

export interface ModelPerformance {
  model_name: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  last_updated: string;
}

// Threat Hunting Types
export interface HuntingFinding {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  timestamp: string;
  details: Record<string, any>;
}

export interface HuntingResult {
  query_type: string;
  data_source: string;
  results: HuntingFinding[];
  hunting_score: number;
  total_findings: number;
  timestamp: string;
}

export interface IoCAnalysis {
  extracted_iocs: Record<string, string[]>;
  analysis_results: IoCAnalysisResult[];
  correlation: IoCCorrelation;
  total_iocs: number;
  timestamp: string;
}

export interface IoCAnalysisResult {
  ioc_type: string;
  ioc_value: string;
  threat_score: number;
  reputation: 'clean' | 'suspicious' | 'malicious';
  threat_feeds: Record<string, any>;
  first_seen?: string;
  last_seen?: string;
}

export interface IoCCorrelation {
  correlation_score: number;
  patterns: IoCPattern[];
  total_iocs: number;
  malicious_count: number;
}

export interface IoCPattern {
  type: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
}

export interface BehavioralAnalysis {
  behavioral_analysis: Record<string, any>;
  overall_risk_score: number;
  risk_level: 'minimal' | 'low' | 'medium' | 'high' | 'critical';
  timestamp: string;
}

export interface ComprehensiveHuntingResult {
  hunting_results: {
    automated_hunting?: HuntingResult;
    ioc_analysis?: IoCAnalysis;
    behavioral_analysis?: BehavioralAnalysis;
  };
  correlation: {
    overall_score: number;
    total_findings: number;
    critical_findings: number;
    risk_level: string;
  };
  overall_threat_score: number;
  timestamp: string;
}

// Incident Response Types
export interface ResponseAction {
  action: 'isolate' | 'block' | 'revoke' | 'quarantine' | 'monitor' | 'alert' | 'backup' | 'patch';
  description: string;
  severity: 'low' | 'medium' | 'high';
  execution_time: number;
  effectiveness: number;
  probability: number;
}

export interface ResponseSelection {
  selected_actions: ResponseAction[];
  action_probabilities: number[];
  response_confidence: number;
  expected_effectiveness: number;
  estimated_execution_time: number;
  risk_assessment: 'low' | 'medium' | 'high';
  timestamp: string;
}

export interface ExecutionResult {
  execution_results: ExecutionActionResult[];
  overall_status: 'all_successful' | 'partially_successful' | 'all_failed' | 'no_actions';
  successful_actions: number;
  failed_actions: number;
  total_execution_time: number;
  timestamp: string;
}

export interface ExecutionActionResult {
  action: string;
  status: 'success' | 'failed';
  platform?: string;
  execution_time: number;
  details?: any;
  error?: string;
}

export interface SOARPlatform {
  enabled: boolean;
  status: 'online' | 'offline' | 'error';
  last_check: string;
  capabilities: string[];
  error?: string;
}

export interface SOARStatus {
  platforms: Record<string, SOARPlatform>;
  total_platforms: number;
  active_platforms: number;
}

export interface IncidentData {
  severity: 'low' | 'medium' | 'high' | 'critical';
  threat_type: string;
  affected_systems: number;
  user_impact: 'low' | 'medium' | 'high' | 'critical';
  business_critical: boolean;
  detection_time: string;
}

export interface IncidentResponseResponse {
  incident_id: number;
  response_selection: ResponseSelection;
  execution_result: ExecutionResult;
  overall_status: string;
  timestamp: string;
}

// Dashboard and Statistics Types
export interface DashboardStats {
  total_users: number;
  active_sessions: number;
  total_threats: number;
  active_incidents: number;
  system_health: 'healthy' | 'warning' | 'critical';
  last_updated: string;
}

export interface AccessControlStats {
  period: string;
  total_assessments: number;
  average_tps: number;
  decisions: Record<string, number>;
  active_connections: number;
}

export interface ThreatPredictionStats {
  period: string;
  total_predictions: number;
  predictions_by_type: Record<string, number>;
  average_confidence: number;
  zero_day_detections: number;
  model_accuracy: number;
}

export interface ThreatHuntingStats {
  period: string;
  total_hunts: number;
  results_by_type: Record<string, number>;
  average_confidence: number;
  critical_findings: number;
  hunting_efficiency: number;
}

export interface IncidentResponseStats {
  total_incidents: number;
  incidents_by_severity: Record<string, number>;
  incidents_by_status: Record<string, number>;
  average_response_time_minutes: number;
  response_effectiveness_percentage: number;
  automation_rate: number;
  soar_integration_status: string;
}

// WebSocket Message Types
export interface WebSocketMessage {
  type: 'risk_update' | 'threat_alert' | 'incident_update' | 'system_status';
  data: any;
  timestamp: string;
}

export interface RiskUpdateMessage {
  type: 'risk_update';
  user_id: number;
  tps_score: number;
  decision: string;
  timestamp: string;
}

// API Response Types
export interface ApiResponse<T> {
  data: T;
  message?: string;
  success: boolean;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

// Form Types
export interface LoginForm {
  username: string;
  password: string;
}

export interface RiskAssessmentForm {
  context: Record<string, any>;
  device_info: DeviceInfo;
  network_type: string;
  ip_address: string;
}

export interface ThreatPredictionForm {
  network_data: NetworkData;
  source: string;
  timestamp?: string;
}

export interface HuntingQueryForm {
  data_source: string;
  query_type: 'apt_detection' | 'malware_detection' | 'insider_threat';
  filters: Record<string, any>;
}

export interface IncidentResponseForm {
  incident_data: IncidentData;
  threat_data: {
    confidence: number;
    type: string;
    source: string;
  };
}

// Chart Data Types
export interface ChartDataPoint {
  name: string;
  value: number;
  timestamp?: string;
}

export interface TimeSeriesData {
  timestamp: string;
  value: number;
  category?: string;
}

export interface PieChartData {
  name: string;
  value: number;
  color?: string;
}

export interface BarChartData {
  category: string;
  value: number;
  color?: string;
}

// Notification Types
export interface Notification {
  id: string;
  type: 'info' | 'success' | 'warning' | 'error';
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
}

// Filter and Search Types
export interface FilterOptions {
  dateRange?: [Date, Date];
  severity?: string[];
  status?: string[];
  user?: string[];
  search?: string;
}

export interface SortOptions {
  field: string;
  direction: 'asc' | 'desc';
}

// Error Types
export interface ApiError {
  message: string;
  code: string;
  details?: any;
}

// Loading States
export interface LoadingState {
  loading: boolean;
  error: string | null;
  data: any;
}

// Real-time Updates
export interface RealTimeUpdate {
  component: string;
  action: 'create' | 'update' | 'delete';
  data: any;
  timestamp: string;
} 