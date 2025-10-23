# AISF Security Platform - Backend

Advanced Intelligent Security Framework (AISF) Backend Implementation

## Overview

This is the backend implementation of the AISF Security Platform, featuring four core components:

1. **Real-Time Context-Based Access Control** - Risk-based access management with behavioral anomaly detection
2. **Predictive Threat Anticipation** - ML-powered threat detection and classification
3. **Continuous Threat Hunting** - Automated threat discovery and IoC correlation
4. **Automated Incident Response** - AI-driven response action selection and execution

## Technology Stack

- **Framework**: FastAPI with async/await support
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Cache**: Redis for real-time data
- **Authentication**: JWT-based with role-based access control
- **ML Libraries**: scikit-learn, TensorFlow/Keras, pandas, numpy
- **Real-time**: WebSocket support for live updates
- **Documentation**: Auto-generated OpenAPI/Swagger docs

## Project Structure

```
backend/
├── app/
│   ├── api/
│   │   ├── components/          # Core AISF component logic
│   │   │   ├── access_control.py
│   │   │   ├── threat_prediction.py
│   │   │   ├── threat_hunting.py
│   │   │   └── incident_response.py
│   │   ├── routes/              # API route handlers
│   │   │   ├── access_control.py
│   │   │   ├── threat_prediction.py
│   │   │   ├── threat_hunting.py
│   │   │   └── incident_response.py
│   │   ├── auth/                # Authentication & authorization
│   │   └── utils/               # Shared utilities
│   ├── core/                    # Core configuration
│   │   ├── config.py
│   │   └── database.py
│   ├── models/                  # Database models
│   │   ├── user.py
│   │   ├── risk_assessment.py
│   │   ├── threat.py
│   │   ├── incident.py
│   │   └── audit_log.py
│   ├── ml_models/               # ML model implementations
│   │   ├── threat_classifier.py
│   │   ├── anomaly_detector.py
│   │   ├── response_optimizer.py
│   │   └── train_models.py
│   └── utils/                   # Utility scripts
│       └── demo_data_generator.py
├── requirements.txt
└── README.md
```

## Installation & Setup

### Prerequisites

- Python 3.8+
- PostgreSQL 12+
- Redis 6+
- pip

### 1. Clone and Setup

```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Database Setup

```bash
# Create PostgreSQL database
createdb aisf_db

# Run database migrations
alembic upgrade head
```

### 3. Environment Configuration

Create a `.env` file in the backend directory:

```env
# Database
POSTGRES_SERVER=localhost
POSTGRES_USER=postgres
POSTGRES_PASSWORD=password
POSTGRES_DB=aisf_db

# Redis
REDIS_URL=redis://localhost:6379/0

# Security
SECRET_KEY=your-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=1440
REFRESH_TOKEN_EXPIRE_MINUTES=10080

# CORS
CORS_ORIGINS=["http://localhost:3000"]
```

### 4. Start Services

```bash
# Start Redis (if not running)
redis-server

# Start PostgreSQL (if not running)
# Platform-specific commands

# Start the FastAPI server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## API Documentation

Once the server is running, access the interactive API documentation:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Core Components

### 1. Access Control (`/api/access-control`)

**Key Features:**
- Real-time risk scoring using TPS (Threat Probability Score)
- Behavioral anomaly detection with GMM
- Dynamic access control decisions
- WebSocket support for live updates

**Main Endpoints:**
- `POST /assess-risk` - Assess user risk and return access decision
- `POST /user-behavior` - Update user behavior data
- `GET /risk-history/{user_id}` - Get risk assessment history
- `GET /current-risk/{user_id}` - Get current risk assessment
- `WebSocket /ws/risk-updates` - Real-time risk updates

**Example Usage:**
```python
import requests

# Assess user risk
response = requests.post("http://localhost:8000/api/access-control/assess-risk", json={
    "context": {"login_time": "2024-01-15T14:30:00Z"},
    "device_info": {"type": "laptop", "is_known_device": True},
    "network_type": "corporate_wifi",
    "ip_address": "192.168.1.100"
})
```

### 2. Threat Prediction (`/api/threat-prediction`)

**Key Features:**
- ML-powered threat classification (Random Forest, LSTM)
- Zero-day attack detection using autoencoders
- Threat intelligence confidence scoring
- Real-time threat prediction

**Main Endpoints:**
- `POST /predict-threat` - Predict threat type and confidence
- `POST /threat-intelligence` - Enrich threat data with intelligence
- `POST /zero-day-detection` - Detect zero-day attacks
- `GET /model-performance` - Get ML model performance metrics

**Example Usage:**
```python
# Predict threat
response = requests.post("http://localhost:8000/api/threat-prediction/predict-threat", json={
    "network_data": {
        "duration": 100,
        "src_bytes": 1000,
        "dst_bytes": 0,
        "count": 50
    }
})
```

### 3. Threat Hunting (`/api/threat-hunting`)

**Key Features:**
- Automated threat hunting queries
- IoC correlation and analysis
- Behavioral analysis for insider threats
- Threat feed integration

**Main Endpoints:**
- `POST /hunt-threats` - Perform automated threat hunting
- `POST /ioc-analysis` - Analyze Indicators of Compromise
- `POST /behavioral-analysis` - Analyze user behavior
- `POST /comprehensive-hunt` - Comprehensive threat hunting

**Example Usage:**
```python
# Hunt for threats
response = requests.post("http://localhost:8000/api/threat-hunting/hunt-threats", json={
    "data_source": "network",
    "query_type": "apt_detection",
    "filters": {"time_range": "last_24_hours"}
})
```

### 4. Incident Response (`/api/incident-response`)

**Key Features:**
- PPO-based response action selection
- SOAR platform integration
- Automated response execution
- Response effectiveness tracking

**Main Endpoints:**
- `POST /handle-incident` - Handle incident with automated response
- `POST /select-response` - Select optimal response actions
- `POST /execute-response` - Execute response actions
- `GET /soar-integration` - Get SOAR platform status

**Example Usage:**
```python
# Handle incident
response = requests.post("http://localhost:8000/api/incident-response/handle-incident", json={
    "incident_data": {
        "severity": "high",
        "threat_type": "malware",
        "affected_systems": 5
    },
    "threat_data": {
        "confidence": 85.5,
        "type": "malware"
    }
})
```

## ML Model Training

### Training Scripts

The backend includes comprehensive ML model training scripts:

```bash
# Train all models
python -m app.ml_models.train_models

# Models will be saved to: backend/app/ml_models/saved_models/
```

### Available Models

1. **Threat Classifier**
   - Random Forest (97.69% accuracy target)
   - LSTM for sequential patterns
   - Feature engineering for network traffic

2. **Anomaly Detector**
   - Gaussian Mixture Models (GMM)
   - Autoencoder for zero-day detection
   - Statistical anomaly detection

3. **Response Optimizer**
   - PPO (Proximal Policy Optimization)
   - Reinforcement learning for action selection
   - Policy network for decision making

## Demo Data Generation

Generate realistic demo data for testing:

```bash
# Generate demo data
python -m app.utils.demo_data_generator

# Data will be saved to: backend/app/utils/demo_data.json
```

## Authentication & Authorization

### JWT Authentication

The API uses JWT tokens for authentication:

```python
# Login to get access token
response = requests.post("http://localhost:8000/api/auth/login", json={
    "username": "admin",
    "password": "password"
})

token = response.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}
```

### Role-Based Access Control

Three user roles are supported:
- **Admin**: Full access to all endpoints
- **Analyst**: Access to analysis and monitoring
- **Viewer**: Read-only access to dashboards

## Real-Time Features

### WebSocket Support

Real-time updates are available via WebSocket connections:

```javascript
// Connect to risk updates
const ws = new WebSocket('ws://localhost:8000/api/access-control/ws/risk-updates');

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Risk update:', data);
};
```

## Performance & Scalability

### Caching Strategy

- Redis caching for frequently accessed data
- IP reputation caching (1 hour TTL)
- Model prediction caching
- Session data caching

### Database Optimization

- Indexed queries for performance
- Connection pooling
- Async database operations
- Efficient data models

## Security Features

### Implemented Security Measures

1. **Authentication & Authorization**
   - JWT-based authentication
   - Role-based access control
   - Token refresh mechanism

2. **Input Validation**
   - Pydantic models for request validation
   - SQL injection prevention
   - XSS protection

3. **Audit Logging**
   - Comprehensive audit trail
   - User action tracking
   - Security event logging

4. **Rate Limiting**
   - API rate limiting
   - Brute force protection
   - DDoS mitigation

## Testing

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run tests
pytest

# Run with coverage
pytest --cov=app
```

### Test Structure

```
tests/
├── test_access_control.py
├── test_threat_prediction.py
├── test_threat_hunting.py
├── test_incident_response.py
└── test_auth.py
```

## Monitoring & Logging

### Health Checks

```bash
# Health check endpoint
curl http://localhost:8000/health
```

### Logging Configuration

Logs are configured for different levels:
- **INFO**: General application logs
- **WARNING**: Security warnings
- **ERROR**: Error conditions
- **DEBUG**: Detailed debugging information

## Deployment

### Production Deployment

1. **Environment Setup**
   ```bash
   # Set production environment
   export ENVIRONMENT=production
   
   # Use production database
   export POSTGRES_DB=aisf_prod
   ```

2. **Security Configuration**
   ```bash
   # Generate secure secret key
   openssl rand -hex 32
   
   # Update .env with production values
   ```

3. **Start Production Server**
   ```bash
   # Use production server
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
   ```

### Docker Deployment

```dockerfile
# Dockerfile example
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

## Troubleshooting

### Common Issues

1. **Database Connection Errors**
   - Check PostgreSQL service status
   - Verify database credentials
   - Ensure database exists

2. **Redis Connection Errors**
   - Check Redis service status
   - Verify Redis URL configuration
   - Check network connectivity

3. **ML Model Loading Errors**
   - Ensure models are trained
   - Check model file paths
   - Verify TensorFlow installation

### Debug Mode

Enable debug mode for detailed logging:

```bash
export LOG_LEVEL=DEBUG
uvicorn app.main:app --reload --log-level debug
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue on GitHub
- Contact the development team
- Check the documentation

---

**AISF Security Platform** - Advanced Intelligent Security Framework 