import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import { ThreatPredictionResponse, ThreatPredictionStats } from '../../types';
import { threatPredictionService } from '../../services';

interface ThreatPredictionState {
  currentPrediction: ThreatPredictionResponse | null;
  threatHistory: any[];
  stats: ThreatPredictionStats | null;
  modelPerformance: any;
  loading: boolean;
  error: string | null;
}

const initialState: ThreatPredictionState = {
  currentPrediction: null,
  threatHistory: [],
  stats: null,
  modelPerformance: null,
  loading: false,
  error: null,
};

export const predictThreat = createAsyncThunk(
  'threatPrediction/predictThreat',
  async (networkData: any) => {
    const response = await threatPredictionService.predictThreat(networkData);
    return response;
  }
);

export const getThreatHistory = createAsyncThunk(
  'threatPrediction/getThreatHistory',
  async ({ limit, threatType, minConfidence }: { limit?: number; threatType?: string; minConfidence?: number }) => {
    const response = await threatPredictionService.getThreatHistory(limit, threatType, minConfidence);
    return response;
  }
);

export const getModelPerformance = createAsyncThunk(
  'threatPrediction/getModelPerformance',
  async () => {
    const response = await threatPredictionService.getModelPerformance();
    return response;
  }
);

export const getStats = createAsyncThunk(
  'threatPrediction/getStats',
  async () => {
    const response = await threatPredictionService.getPredictionStats();
    return response;
  }
);

const threatPredictionSlice = createSlice({
  name: 'threatPrediction',
  initialState,
  reducers: {
    setCurrentPrediction: (state, action: PayloadAction<ThreatPredictionResponse>) => {
      state.currentPrediction = action.payload;
    },
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(predictThreat.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(predictThreat.fulfilled, (state, action) => {
        state.loading = false;
        state.currentPrediction = action.payload;
      })
      .addCase(predictThreat.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to predict threat';
      })
      .addCase(getThreatHistory.fulfilled, (state, action) => {
        state.threatHistory = action.payload.threats;
      })
      .addCase(getModelPerformance.fulfilled, (state, action) => {
        state.modelPerformance = action.payload;
      })
      .addCase(getStats.fulfilled, (state, action) => {
        state.stats = action.payload;
      });
  },
});

export const { setCurrentPrediction, clearError } = threatPredictionSlice.actions;
export default threatPredictionSlice.reducer; 