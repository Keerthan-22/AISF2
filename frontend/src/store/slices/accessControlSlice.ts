import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import { RiskAssessmentResponse, AccessControlStats } from '../../types';
import { accessControlService } from '../../services';

interface AccessControlState {
  currentRisk: RiskAssessmentResponse | null;
  riskHistory: any[];
  stats: AccessControlStats | null;
  loading: boolean;
  error: string | null;
}

const initialState: AccessControlState = {
  currentRisk: null,
  riskHistory: [],
  stats: null,
  loading: false,
  error: null,
};

export const assessRisk = createAsyncThunk(
  'accessControl/assessRisk',
  async (request: any) => {
    const response = await accessControlService.assessRisk(request);
    return response;
  }
);

export const getRiskHistory = createAsyncThunk(
  'accessControl/getRiskHistory',
  async ({ userId, limit }: { userId: number; limit?: number }) => {
    const response = await accessControlService.getRiskHistory(userId, limit);
    return response;
  }
);

export const getStats = createAsyncThunk(
  'accessControl/getStats',
  async () => {
    const response = await accessControlService.getStats();
    return response;
  }
);

const accessControlSlice = createSlice({
  name: 'accessControl',
  initialState,
  reducers: {
    setCurrentRisk: (state, action: PayloadAction<RiskAssessmentResponse>) => {
      state.currentRisk = action.payload;
    },
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(assessRisk.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(assessRisk.fulfilled, (state, action) => {
        state.loading = false;
        state.currentRisk = action.payload;
      })
      .addCase(assessRisk.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to assess risk';
      })
      .addCase(getRiskHistory.pending, (state) => {
        state.loading = true;
      })
      .addCase(getRiskHistory.fulfilled, (state, action) => {
        state.loading = false;
        state.riskHistory = action.payload.assessments;
      })
      .addCase(getRiskHistory.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to get risk history';
      })
      .addCase(getStats.fulfilled, (state, action) => {
        state.stats = action.payload;
      });
  },
});

export const { setCurrentRisk, clearError } = accessControlSlice.actions;
export default accessControlSlice.reducer; 