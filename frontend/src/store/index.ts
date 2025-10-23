// AISF Redux Store Configuration

import { configureStore } from '@reduxjs/toolkit';
import { TypedUseSelectorHook, useDispatch, useSelector } from 'react-redux';
import authReducer from './slices/authSlice';
import accessControlReducer from './slices/accessControlSlice';
import threatPredictionReducer from './slices/threatPredictionSlice';
import threatHuntingReducer from './slices/threatHuntingSlice';
import incidentResponseReducer from './slices/incidentResponseSlice';
import notificationReducer from './slices/notificationSlice';

export const store = configureStore({
  reducer: {
    auth: authReducer,
    accessControl: accessControlReducer,
    threatPrediction: threatPredictionReducer,
    threatHunting: threatHuntingReducer,
    incidentResponse: incidentResponseReducer,
    notifications: notificationReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: ['persist/PERSIST'],
      },
    }),
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;

// Use throughout your app instead of plain `useDispatch` and `useSelector`
export const useAppDispatch = () => useDispatch<AppDispatch>();
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector; 