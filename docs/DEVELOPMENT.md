# Development Guide

Guide for developers contributing to or modifying the HomeLab PKI Platform.

## Development Environment Setup

### Prerequisites

- Docker Desktop 20.10+
- Docker Compose 2.0+
- Git
- Code editor (VS Code recommended)
- Node.js 18+ (for frontend development)
- Python 3.11+ (for backend development)

### Clone and Setup

```bash
# Clone repository
git clone <repository-url>
cd pki

# Copy environment config
cp .env.example .env.development

# Edit development config
nano .env.development
```

### Development Configuration

`.env.development`:
```bash
# Development mode
ENVIRONMENT=development
DEBUG=true
LOG_LEVEL=DEBUG

# Point to the bundled Vault service
VAULT_DEV_MODE=false
VAULT_ADDR=http://vault:8200
VAULT_TOKEN=dev-root-token

# Disable email in development
SMTP_ENABLED=false

# Fast check intervals for testing
HEALTH_CHECK_INTERVAL=60
```

### Start Development Environment

```bash
# Start all services
docker-compose -f docker-compose.dev.yml up

# Or start with rebuild
docker-compose -f docker-compose.dev.yml up --build

# Start in background
docker-compose -f docker-compose.dev.yml up -d
```

## Project Structure

```
pki/
├── backend/                 # Python FastAPI backend
│   ├── app/
│   │   ├── api/            # API endpoints
│   │   │   ├── v1/
│   │   │   │   ├── auth.py
│   │   │   │   ├── certificates.py
│   │   │   │   ├── ca.py
│   │   │   │   ├── monitoring.py
│   │   │   │   └── alerts.py
│   │   │   └── deps.py     # Dependencies
│   │   ├── core/           # Core functionality
│   │   │   ├── config.py
│   │   │   ├── security.py
│   │   │   ├── vault.py
│   │   │   └── pki.py      # PKI operations
│   │   ├── db/             # Database
│   │   │   ├── models.py
│   │   │   ├── schemas.py
│   │   │   └── session.py
│   │   ├── services/       # Business logic
│   │   │   ├── certificate_service.py
│   │   │   ├── monitoring_service.py
│   │   │   └── alert_service.py
│   │   └── main.py
│   ├── tests/              # Backend tests
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/               # React frontend
│   ├── src/
│   │   ├── components/    # React components
│   │   │   ├── certificates/
│   │   │   ├── monitoring/
│   │   │   ├── alerts/
│   │   │   ├── layout/
│   │   │   └── common/
│   │   ├── pages/         # Page components
│   │   ├── services/      # API services
│   │   ├── hooks/         # Custom hooks
│   │   ├── utils/         # Utilities
│   │   ├── types/         # TypeScript types
│   │   └── App.tsx
│   ├── public/
│   ├── package.json
│   └── Dockerfile
├── monitor/               # Monitoring service
│   ├── app/
│   │   ├── checker.py    # Health check logic
│   │   ├── scheduler.py  # Job scheduling
│   │   └── main.py
│   ├── requirements.txt
│   └── Dockerfile
├── nginx/                # Nginx configuration
│   ├── nginx.conf
│   └── ssl/
├── docs/                 # Documentation
├── scripts/              # Utility scripts
│   ├── init-db.sh
│   ├── backup.sh
│   └── restore.sh
├── docker-compose.yml    # Production compose
├── docker-compose.dev.yml # Development compose
├── .env.example
├── .gitignore
└── README.md
```

## Backend Development

### Local Development Setup

```bash
cd backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run locally (without Docker)
uvicorn app.main:app --reload --port 8000
```

### Backend Architecture

**Key Components:**

1. **FastAPI Application** (`app/main.py`)
   - Application factory
   - Middleware configuration
   - Router registration

2. **API Routes** (`app/api/v1/`)
   - RESTful endpoints
   - Request/response models
   - Dependency injection

3. **Services** (`app/services/`)
   - Business logic
   - PKI operations
   - Monitoring logic

4. **Core** (`app/core/`)
   - Configuration management
   - Vault integration
   - Security utilities

5. **Database** (`app/db/`)
   - SQLAlchemy models
   - Pydantic schemas
   - Database session management

### Adding New Endpoints

```python
# app/api/v1/example.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api import deps
from app.db import schemas

router = APIRouter()

@router.post("/example", response_model=schemas.ExampleResponse)
def create_example(
    example: schemas.ExampleCreate,
    db: Session = Depends(deps.get_db),
    current_user = Depends(deps.get_current_user)
):
    """Create a new example resource"""
    # Validate input
    if not example.name:
        raise HTTPException(status_code=400, detail="Name is required")
    
    # Business logic
    result = service.create_example(db, example, current_user)
    
    return result
```

Register in `app/main.py`:
```python
from app.api.v1 import example

app.include_router(example.router, prefix="/api/v1/example", tags=["example"])
```

### Database Migrations

```bash
# Install Alembic
pip install alembic

# Initialize migrations (first time only)
alembic init migrations

# Create migration
alembic revision --autogenerate -m "Add example table"

# Apply migrations
alembic upgrade head

# Rollback
alembic downgrade -1
```

### Testing Backend

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_certificates.py

# Run specific test
pytest tests/test_certificates.py::test_issue_certificate
```

Example test:
```python
# tests/test_certificates.py
import pytest
from fastapi.testclient import TestClient

def test_issue_certificate(client: TestClient, admin_token: str):
    """Test certificate issuance"""
    response = client.post(
        "/api/v1/certificates/issue",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "common_name": "test.local",
            "validity_days": 365,
            "key_size": 2048
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["common_name"] == "test.local"
    assert "serial_number" in data
```

## Frontend Development

### Local Development Setup

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm start

# Open browser at http://localhost:3000
```

### Frontend Architecture

**Tech Stack:**
- React 18
- TypeScript
- TailwindCSS
- React Router
- React Query (data fetching)
- Axios (HTTP client)

**Key Directories:**

```
src/
├── components/         # Reusable components
│   ├── certificates/
│   │   ├── CertificateList.tsx
│   │   ├── CertificateForm.tsx
│   │   └── CertificateDetails.tsx
│   ├── monitoring/
│   └── common/
│       ├── Button.tsx
│       ├── Input.tsx
│       └── Modal.tsx
├── pages/             # Page components
│   ├── Dashboard.tsx
│   ├── Certificates.tsx
│   ├── Monitoring.tsx
│   └── Settings.tsx
├── services/          # API services
│   ├── api.ts
│   ├── auth.ts
│   └── certificates.ts
├── hooks/             # Custom React hooks
│   ├── useAuth.ts
│   ├── useCertificates.ts
│   └── useMonitoring.ts
├── types/             # TypeScript types
│   └── index.ts
└── utils/             # Utility functions
    └── helpers.ts
```

### Creating Components

```typescript
// src/components/certificates/CertificateCard.tsx
import React from 'react';
import { Certificate } from '../../types';

interface CertificateCardProps {
  certificate: Certificate;
  onSelect: (id: string) => void;
}

export const CertificateCard: React.FC<CertificateCardProps> = ({
  certificate,
  onSelect
}) => {
  const expiresIn = calculateDaysUntilExpiry(certificate.valid_until);
  const statusColor = expiresIn < 30 ? 'text-red-600' : 'text-green-600';

  return (
    <div className="border rounded-lg p-4 hover:shadow-lg cursor-pointer"
         onClick={() => onSelect(certificate.id)}>
      <h3 className="text-lg font-semibold">{certificate.common_name}</h3>
      <p className={`text-sm ${statusColor}`}>
        Expires in {expiresIn} days
      </p>
    </div>
  );
};
```

### API Integration

```typescript
// src/services/certificates.ts
import axios from 'axios';
import { Certificate, IssueCertificateRequest } from '../types';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export const certificatesAPI = {
  list: async (): Promise<Certificate[]> => {
    const response = await axios.get(`${API_BASE}/api/v1/certificates`);
    return response.data;
  },

  issue: async (data: IssueCertificateRequest): Promise<Certificate> => {
    const response = await axios.post(`${API_BASE}/api/v1/certificates/issue`, data);
    return response.data;
  },

  get: async (id: string): Promise<Certificate> => {
    const response = await axios.get(`${API_BASE}/api/v1/certificates/${id}`);
    return response.data;
  }
};
```

### Using React Query

```typescript
// src/hooks/useCertificates.ts
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { certificatesAPI } from '../services/certificates';

export const useCertificates = () => {
  const queryClient = useQueryClient();

  const { data: certificates, isLoading } = useQuery(
    'certificates',
    certificatesAPI.list
  );

  const issueMutation = useMutation(
    certificatesAPI.issue,
    {
      onSuccess: () => {
        queryClient.invalidateQueries('certificates');
      }
    }
  );

  return {
    certificates,
    isLoading,
    issueCertificate: issueMutation.mutate
  };
};
```

### Testing Frontend

```bash
# Run tests
npm test

# Run with coverage
npm test -- --coverage

# Run in watch mode
npm test -- --watch
```

Example test:
```typescript
// src/components/certificates/CertificateCard.test.tsx
import { render, screen, fireEvent } from '@testing-library/react';
import { CertificateCard } from './CertificateCard';

describe('CertificateCard', () => {
  const mockCertificate = {
    id: '1',
    common_name: 'test.local',
    valid_until: '2026-01-01T00:00:00Z',
    status: 'active'
  };

  it('renders certificate information', () => {
    render(<CertificateCard certificate={mockCertificate} onSelect={jest.fn()} />);
    expect(screen.getByText('test.local')).toBeInTheDocument();
  });

  it('calls onSelect when clicked', () => {
    const onSelect = jest.fn();
    render(<CertificateCard certificate={mockCertificate} onSelect={onSelect} />);
    fireEvent.click(screen.getByText('test.local'));
    expect(onSelect).toHaveBeenCalledWith('1');
  });
});
```

## Monitor Service Development

### Local Development

```bash
cd monitor

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run locally
python -m app.main
```

### Adding Health Checks

```python
# app/checker.py
async def check_service_health(service_url: str) -> HealthCheckResult:
    """Perform health check on a service"""
    try:
        start_time = time.time()
        
        # Make HTTPS request
        async with aiohttp.ClientSession() as session:
            async with session.get(service_url, timeout=10) as response:
                response_time = (time.time() - start_time) * 1000
                
                # Check SSL certificate
                ssl_info = await validate_ssl_certificate(response)
                
                return HealthCheckResult(
                    status="healthy" if response.status == 200 else "unhealthy",
                    response_time_ms=response_time,
                    status_code=response.status,
                    ssl_valid=ssl_info.valid,
                    ssl_expires_in_days=ssl_info.days_until_expiry
                )
    except Exception as e:
        return HealthCheckResult(
            status="down",
            error=str(e)
        )
```

## Database Development

### Schema Design

```python
# app/db/models.py
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.db.base import Base

class Certificate(Base):
    __tablename__ = "certificates"
    
    id = Column(String, primary_key=True)
    ca_id = Column(String, ForeignKey("ca_certificates.id"))
    common_name = Column(String, nullable=False, index=True)
    serial_number = Column(String, unique=True, nullable=False)
    valid_from = Column(DateTime, nullable=False)
    valid_until = Column(DateTime, nullable=False, index=True)
    status = Column(String, nullable=False, index=True)
    vault_key_path = Column(String)
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    ca = relationship("CACertificate", back_populates="certificates")
    monitors = relationship("ServiceMonitor", back_populates="certificate")
```

### Queries and Indexes

```python
# Efficient queries
def get_expiring_certificates(db: Session, days: int = 30):
    """Get certificates expiring within specified days"""
    expiry_date = datetime.now() + timedelta(days=days)
    return db.query(Certificate)\
        .filter(Certificate.valid_until <= expiry_date)\
        .filter(Certificate.status == "active")\
        .all()

# Add indexes for performance
# In migration file:
op.create_index('ix_certificates_status_expiry', 'certificates', ['status', 'valid_until'])
```

## Code Style and Standards

### Python (Backend)

**Style Guide:** PEP 8

```bash
# Format code
black app/

# Sort imports
isort app/

# Lint
flake8 app/
pylint app/

# Type checking
mypy app/
```

**Example:**
```python
from typing import List, Optional
from pydantic import BaseModel

class CertificateCreate(BaseModel):
    """Schema for certificate creation request"""
    common_name: str
    san_entries: Optional[List[str]] = None
    validity_days: int = 3650
    key_size: int = 4096
    
    class Config:
        schema_extra = {
            "example": {
                "common_name": "test.local",
                "san_entries": ["test.local", "192.168.1.100"],
                "validity_days": 3650,
                "key_size": 4096
            }
        }
```

### TypeScript (Frontend)

**Style Guide:** Airbnb

```bash
# Format code
npm run format

# Lint
npm run lint

# Type check
npm run type-check
```

**Example:**
```typescript
interface Certificate {
  id: string;
  commonName: string;
  validFrom: string;
  validUntil: string;
  status: 'active' | 'expired' | 'revoked';
}

const formatExpiryDate = (date: string): string => {
  return new Date(date).toLocaleDateString();
};
```

## Git Workflow

### Branch Strategy

```
main              # Production-ready code
  └── develop     # Integration branch
      ├── feature/certificate-templates
      ├── feature/monitoring-improvements
      └── bugfix/issue-123
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

**Examples:**
```
feat(certificates): add certificate templates

Add support for certificate templates to allow quick issuance
with predefined settings.

Closes #123
```

```
fix(monitoring): correct response time calculation

Response time was calculated incorrectly, showing microseconds
instead of milliseconds.
```

### Pull Request Process

1. Create feature branch from `develop`
2. Make changes with clear commits
3. Add tests for new features
4. Update documentation
5. Run linters and tests
6. Create PR to `develop`
7. Wait for code review
8. Address review comments
9. Merge when approved

## Debugging

### Backend Debugging

**Using VS Code:**

`.vscode/launch.json`:
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Python: FastAPI",
      "type": "python",
      "request": "launch",
      "module": "uvicorn",
      "args": [
        "app.main:app",
        "--reload",
        "--port", "8000"
      ],
      "jinja": true
    }
  ]
}
```

**Debug with Docker:**
```bash
# Attach to running container
docker-compose exec backend bash

# Check logs
docker-compose logs -f backend

# Use pdb
import pdb; pdb.set_trace()
```

### Frontend Debugging

**Browser DevTools:**
- Use React DevTools extension
- Check Network tab for API calls
- Use Console for errors

**VS Code Debugger:**

`.vscode/launch.json`:
```json
{
  "name": "Chrome",
  "type": "chrome",
  "request": "launch",
  "url": "http://localhost:3000",
  "webRoot": "${workspaceFolder}/frontend/src"
}
```

## Performance Optimization

### Backend

```python
# Use database connection pooling
engine = create_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=40
)

# Cache expensive operations
from functools import lru_cache

@lru_cache(maxsize=100)
def get_ca_certificate():
    return load_ca_from_vault()

# Async operations
async def batch_health_checks(urls: List[str]):
    async with aiohttp.ClientSession() as session:
        tasks = [check_url(session, url) for url in urls]
        return await asyncio.gather(*tasks)
```

### Frontend

```typescript
// Code splitting
const CertificateDetails = React.lazy(() => import('./CertificateDetails'));

// Memoization
const MemoizedCertificateList = React.memo(CertificateList);

// Optimize re-renders
const { certificates } = useCertificates();
const filteredCerts = useMemo(
  () => certificates.filter(c => c.status === 'active'),
  [certificates]
);
```

## Documentation

### Code Documentation

```python
# Python docstrings
def issue_certificate(
    db: Session,
    common_name: str,
    validity_days: int = 3650
) -> Certificate:
    """
    Issue a new SSL/TLS certificate.
    
    Args:
        db: Database session
        common_name: Primary hostname for the certificate
        validity_days: Certificate validity period in days (default: 3650)
        
    Returns:
        Certificate: The issued certificate object
        
    Raises:
        ValueError: If common_name is invalid
        VaultError: If key storage fails
        
    Example:
        >>> cert = issue_certificate(db, "test.local", 365)
        >>> print(cert.serial_number)
        '1A:2B:3C:4D'
    """
```

```typescript
// TypeScript JSDoc
/**
 * Fetches a certificate by ID
 * @param id - Certificate ID
 * @returns Promise resolving to certificate data
 * @throws {Error} If certificate not found
 */
async function getCertificate(id: string): Promise<Certificate> {
  // Implementation
}
```

## See Also

- [API Documentation](API.md)
- [Database Schema](DATABASE.md)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Deployment Guide](DEPLOYMENT.md)
