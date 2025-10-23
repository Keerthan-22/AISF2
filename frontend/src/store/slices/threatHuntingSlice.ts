import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import { ComprehensiveHuntingResult, ThreatHuntingStats } from '../../types';
import { threatHuntingService } from '../../services';

interface ThreatHuntingState {
  currentHunt: ComprehensiveHuntingResult | null;
  huntingHistory: any[];
  stats: ThreatHuntingStats | null;
  availableQueries: any;
  iocPatterns: any;
  loading: boolean;
  error: string | null;
}

const initialState: ThreatHuntingState = {
  currentHunt: null,
  huntingHistory: [],
  stats: null,
  availableQueries: null,
  iocPatterns: null,
  loading: false,
  error: null,
};

export const huntThreats = createAsyncThunk(
  'threatHunting/huntThreats',
  async ({ dataSource, queryType, filters }: { dataSource: string; queryType: string; filters: any }) => {
    const response = await threatHuntingService.huntThreats(dataSource, queryType, filters);
    return response;
  }
);

export const comprehensiveHunt = createAsyncThunk(
  'threatHunting/comprehensiveHunt',
  async (huntingData: any) => {
    const response = await threatHuntingService.comprehensiveHunt(huntingData);
    return response;
  }
);

export const getHuntingHistory = createAsyncThunk(
  'threatHunting/getHuntingHistory',
  async ({ limit, queryType, minScore }: { limit?: number; queryType?: string; minScore?: number }) => {
    const response = await threatHuntingService.getHuntingHistory(limit, queryType, minScore);
    return response;
  }
);

export const getStats = createAsyncThunk(
  'threatHunting/getStats',
  async () => {
    const response = await threatHuntingService.getHuntingStats();
    return response;
  }
);

const threatHuntingSlice = createSlice({
  name: 'threatHunting',
  initialState,
  reducers: {
    setCurrentHunt: (state, action: PayloadAction<ComprehensiveHuntingResult>) => {
      state.currentHunt = action.payload;
    },
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(huntThreats.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(huntThreats.fulfilled, (state, action) => {
        state.loading = false;
      })
      .addCase(huntThreats.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to hunt threats';
      })
      .addCase(comprehensiveHunt.fulfilled, (state, action) => {
        state.currentHunt = action.payload;
      })
      .addCase(getHuntingHistory.fulfilled, (state, action) => {
        state.huntingHistory = action.payload.hunting_history;
      })
      .addCase(getStats.fulfilled, (state, action) => {
        state.stats = action.payload;
      });
  },
});

export const { setCurrentHunt, clearError } = threatHuntingSlice.actions;
export default threatHuntingSlice.reducer; 