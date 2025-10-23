import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';

// Types
export interface Notification {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
  action?: {
    label: string;
    onClick: () => void;
  };
}

export interface Alert {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  timestamp: string;
  acknowledged: boolean;
  source: string;
  category: string;
}

interface NotificationState {
  notifications: Notification[];
  alerts: Alert[];
  loading: boolean;
  error: string | null;
  unreadCount: number;
  alertCount: number;
}

const initialState: NotificationState = {
  notifications: [],
  alerts: [],
  loading: false,
  error: null,
  unreadCount: 0,
  alertCount: 0,
};

// Async thunks
export const fetchNotifications = createAsyncThunk(
  'notifications/fetchNotifications',
  async () => {
    // In real app, this would be an API call
    const response = await fetch('/api/notifications');
    return response.json();
  }
);

export const fetchAlerts = createAsyncThunk(
  'notifications/fetchAlerts',
  async () => {
    // In real app, this would be an API call
    const response = await fetch('/api/alerts');
    return response.json();
  }
);

export const markNotificationAsRead = createAsyncThunk(
  'notifications/markAsRead',
  async (notificationId: string) => {
    // In real app, this would be an API call
    const response = await fetch(`/api/notifications/${notificationId}/read`, {
      method: 'PUT',
    });
    return response.json();
  }
);

export const acknowledgeAlert = createAsyncThunk(
  'notifications/acknowledgeAlert',
  async (alertId: string) => {
    // In real app, this would be an API call
    const response = await fetch(`/api/alerts/${alertId}/acknowledge`, {
      method: 'PUT',
    });
    return response.json();
  }
);

const notificationSlice = createSlice({
  name: 'notifications',
  initialState,
  reducers: {
    addNotification: (state, action: PayloadAction<Notification>) => {
      state.notifications.unshift(action.payload);
      if (!action.payload.read) {
        state.unreadCount += 1;
      }
    },
    addAlert: (state, action: PayloadAction<Alert>) => {
      state.alerts.unshift(action.payload);
      if (!action.payload.acknowledged) {
        state.alertCount += 1;
      }
    },
    removeNotification: (state, action: PayloadAction<string>) => {
      const notification = state.notifications.find(n => n.id === action.payload);
      if (notification && !notification.read) {
        state.unreadCount -= 1;
      }
      state.notifications = state.notifications.filter(n => n.id !== action.payload);
    },
    removeAlert: (state, action: PayloadAction<string>) => {
      const alert = state.alerts.find(a => a.id === action.payload);
      if (alert && !alert.acknowledged) {
        state.alertCount -= 1;
      }
      state.alerts = state.alerts.filter(a => a.id !== action.payload);
    },
    markAllNotificationsAsRead: (state) => {
      state.notifications.forEach(notification => {
        notification.read = true;
      });
      state.unreadCount = 0;
    },
    acknowledgeAllAlerts: (state) => {
      state.alerts.forEach(alert => {
        alert.acknowledged = true;
      });
      state.alertCount = 0;
    },
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      // Fetch notifications
      .addCase(fetchNotifications.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchNotifications.fulfilled, (state, action) => {
        state.loading = false;
        state.notifications = action.payload;
        state.unreadCount = action.payload.filter((n: Notification) => !n.read).length;
      })
      .addCase(fetchNotifications.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch notifications';
      })
      // Fetch alerts
      .addCase(fetchAlerts.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchAlerts.fulfilled, (state, action) => {
        state.loading = false;
        state.alerts = action.payload;
        state.alertCount = action.payload.filter((a: Alert) => !a.acknowledged).length;
      })
      .addCase(fetchAlerts.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch alerts';
      })
      // Mark notification as read
      .addCase(markNotificationAsRead.fulfilled, (state, action) => {
        const notification = state.notifications.find(n => n.id === action.payload.id);
        if (notification && !notification.read) {
          notification.read = true;
          state.unreadCount -= 1;
        }
      })
      // Acknowledge alert
      .addCase(acknowledgeAlert.fulfilled, (state, action) => {
        const alert = state.alerts.find(a => a.id === action.payload.id);
        if (alert && !alert.acknowledged) {
          alert.acknowledged = true;
          state.alertCount -= 1;
        }
      });
  },
});

export const {
  addNotification,
  addAlert,
  removeNotification,
  removeAlert,
  markAllNotificationsAsRead,
  acknowledgeAllAlerts,
  clearError,
} = notificationSlice.actions;

export default notificationSlice.reducer; 