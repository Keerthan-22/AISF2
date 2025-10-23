import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';

// Types
export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';
  threatType: string;
  affectedSystems: number;
  affectedUsers: number;
  detectedAt: string;
  updatedAt: string;
  assignedTo: string;
  priority: number;
  tags: string[];
  threatData: {
    confidence: number;
    type: string;
    source: string;
  };
}

export interface ResponseAction {
  id: string;
  name: string;
  description: string;
  type: 'automated' | 'manual' | 'semi-automated';
  status: 'pending' | 'running' | 'completed' | 'failed';
  priority: number;
  estimatedTime: number;
  actualTime?: number;
  assignedTo?: string;
  dependencies: string[];
  effectiveness: number;
}

export interface SOARIntegration {
  platform: string;
  status: 'connected' | 'disconnected' | 'error';
  lastSync: string;
  playbooks: number;
  activeCases: number;
  responseTime: number;
}

interface IncidentResponseState {
  incidents: Incident[];
  responseActions: ResponseAction[];
  soarIntegrations: SOARIntegration[];
  loading: boolean;
  error: string | null;
  selectedIncident: Incident | null;
  selectedAction: ResponseAction | null;
}

const initialState: IncidentResponseState = {
  incidents: [],
  responseActions: [],
  soarIntegrations: [],
  loading: false,
  error: null,
  selectedIncident: null,
  selectedAction: null,
};

// Async thunks
export const fetchIncidents = createAsyncThunk(
  'incidentResponse/fetchIncidents',
  async () => {
    // In real app, this would be an API call
    const response = await fetch('/api/incident-response/incidents');
    return response.json();
  }
);

export const createIncident = createAsyncThunk(
  'incidentResponse/createIncident',
  async (incidentData: Partial<Incident>) => {
    // In real app, this would be an API call
    const response = await fetch('/api/incident-response/incidents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(incidentData),
    });
    return response.json();
  }
);

export const fetchResponseActions = createAsyncThunk(
  'incidentResponse/fetchResponseActions',
  async () => {
    // In real app, this would be an API call
    const response = await fetch('/api/incident-response/actions');
    return response.json();
  }
);

export const createResponseAction = createAsyncThunk(
  'incidentResponse/createResponseAction',
  async (actionData: Partial<ResponseAction>) => {
    // In real app, this would be an API call
    const response = await fetch('/api/incident-response/actions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(actionData),
    });
    return response.json();
  }
);

const incidentResponseSlice = createSlice({
  name: 'incidentResponse',
  initialState,
  reducers: {
    setSelectedIncident: (state, action: PayloadAction<Incident | null>) => {
      state.selectedIncident = action.payload;
    },
    setSelectedAction: (state, action: PayloadAction<ResponseAction | null>) => {
      state.selectedAction = action.payload;
    },
    updateIncidentStatus: (state, action: PayloadAction<{ id: string; status: Incident['status'] }>) => {
      const incident = state.incidents.find(inc => inc.id === action.payload.id);
      if (incident) {
        incident.status = action.payload.status;
        incident.updatedAt = new Date().toISOString();
      }
    },
    updateActionStatus: (state, action: PayloadAction<{ id: string; status: ResponseAction['status'] }>) => {
      const responseAction = state.responseActions.find(act => act.id === action.payload.id);
      if (responseAction) {
        responseAction.status = action.payload.status;
      }
    },
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      // Fetch incidents
      .addCase(fetchIncidents.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchIncidents.fulfilled, (state, action) => {
        state.loading = false;
        state.incidents = action.payload;
      })
      .addCase(fetchIncidents.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch incidents';
      })
      // Create incident
      .addCase(createIncident.fulfilled, (state, action) => {
        state.incidents.unshift(action.payload);
      })
      // Fetch response actions
      .addCase(fetchResponseActions.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchResponseActions.fulfilled, (state, action) => {
        state.loading = false;
        state.responseActions = action.payload;
      })
      .addCase(fetchResponseActions.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch response actions';
      })
      // Create response action
      .addCase(createResponseAction.fulfilled, (state, action) => {
        state.responseActions.unshift(action.payload);
      });
  },
});

export const {
  setSelectedIncident,
  setSelectedAction,
  updateIncidentStatus,
  updateActionStatus,
  clearError,
} = incidentResponseSlice.actions;

export default incidentResponseSlice.reducer; 