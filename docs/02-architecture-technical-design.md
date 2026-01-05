# MCP Audit - Architecture and Technical Design Document

## Overview

This document describes the technical architecture, infrastructure design, and technology choices for the MCP Audit platform. The system is designed as a cloud-native application using AWS managed services, with support for on-premise agents to test internal MCP servers.

---

## System Architecture

### High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                USERS                                          │
│                                                                              │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│   │   Browser   │    │  CLI Tool   │    │   CI/CD     │    │  On-Prem    │  │
│   │  (Web App)  │    │(Developers) │    │  Pipeline   │    │   Agent     │  │
│   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘  │
│          │                  │                  │                  │          │
└──────────┼──────────────────┼──────────────────┼──────────────────┼──────────┘
           │                  │                  │                  │
           └──────────────────┼──────────────────┼──────────────────┘
                              │                  │
                              ▼                  ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                              AWS CLOUD                                        │
│                                                                              │
│   ┌────────────────────────────────────────────────────────────────────────┐│
│   │                         EDGE LAYER                                      ││
│   │   CloudFront (CDN) ─── WAF (Security) ─── Route 53 (DNS)               ││
│   └────────────────────────────────────────────────────────────────────────┘│
│                                    │                                         │
│   ┌────────────────────────────────┴───────────────────────────────────────┐│
│   │                         API LAYER                                       ││
│   │   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐   ││
│   │   │   API Gateway   │    │ API Gateway     │    │    Cognito      │   ││
│   │   │    (REST)       │    │  (WebSocket)    │    │ (Authentication)│   ││
│   │   └────────┬────────┘    └────────┬────────┘    └─────────────────┘   ││
│   └────────────┼──────────────────────┼────────────────────────────────────┘│
│                │                      │                                      │
│   ┌────────────┴──────────────────────┴────────────────────────────────────┐│
│   │                       COMPUTE LAYER                                     ││
│   │   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐   ││
│   │   │  Lambda (API)   │    │ Step Functions  │    │ Lambda (Workers)│   ││
│   │   │   Handlers      │    │ (Orchestration) │    │                 │   ││
│   │   └─────────────────┘    └─────────────────┘    └─────────────────┘   ││
│   └────────────────────────────────────────────────────────────────────────┘│
│                                    │                                         │
│   ┌────────────────────────────────┴───────────────────────────────────────┐│
│   │                         DATA LAYER                                      ││
│   │   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐   ││
│   │   │    DynamoDB     │    │       S3        │    │   ElastiCache   │   ││
│   │   │   (Database)    │    │    (Storage)    │    │    (Redis)      │   ││
│   │   └─────────────────┘    └─────────────────┘    └─────────────────┘   ││
│   └────────────────────────────────────────────────────────────────────────┘│
│                                    │                                         │
│   ┌────────────────────────────────┴───────────────────────────────────────┐│
│   │                      MESSAGING LAYER                                    ││
│   │   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐   ││
│   │   │      SQS        │    │      SNS        │    │      SES        │   ││
│   │   │    (Queues)     │    │ (Notifications) │    │    (Email)      │   ││
│   │   └─────────────────┘    └─────────────────┘    └─────────────────┘   ││
│   └────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS
                              ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                         EXTERNAL SYSTEMS                                      │
│                                                                              │
│   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│   │   GitHub API    │    │  Target MCPs    │    │   CVE Database  │         │
│   │  (Discovery)    │    │   (Testing)     │    │ (Supply Chain)  │         │
│   └─────────────────┘    └─────────────────┘    └─────────────────┘         │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Technology Stack

### Frontend

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Framework** | React 18 with TypeScript | Single-page application |
| **State Management** | React Query (TanStack Query) | Server state, caching |
| **UI Components** | Tailwind CSS + Headless UI | Styling, accessible components |
| **Build Tool** | Vite | Fast development builds |
| **Hosting** | S3 + CloudFront | Static site hosting with CDN |

### Backend

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Runtime** | Python 3.11 | Lambda functions |
| **API Framework** | AWS Lambda + API Gateway | Serverless REST API |
| **Real-time** | API Gateway WebSocket | Live progress updates |
| **Orchestration** | AWS Step Functions | Test workflow management |
| **Authentication** | Amazon Cognito | User auth, OAuth, JWT |

### Data Storage

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Primary Database** | Amazon DynamoDB | Users, scans, findings |
| **File Storage** | Amazon S3 | Reports, exports, configs |
| **Cache** | Amazon ElastiCache (Redis) | Sessions, rate limiting |
| **Secrets** | AWS Secrets Manager | API keys, credentials |

### Messaging & Notifications

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Job Queues** | Amazon SQS | Async task processing |
| **Pub/Sub** | Amazon SNS | Event notifications |
| **Email** | Amazon SES | Alert emails, reports |

### Infrastructure & DevOps

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Infrastructure as Code** | AWS CDK (TypeScript) | Infrastructure provisioning |
| **CI/CD** | GitHub Actions | Build, test, deploy |
| **Monitoring** | CloudWatch + X-Ray | Logs, metrics, tracing |
| **Security** | AWS WAF | API protection |

### CLI & Agent

| Component | Technology | Purpose |
|-----------|------------|---------|
| **CLI Framework** | Python Click | Command-line interface |
| **MCP Client** | Custom Python library | MCP protocol communication |
| **Agent Runtime** | Docker | On-premise deployment |
| **Distribution** | PyPI + Docker Hub | Package distribution |

---

## AWS Services Detail

### Amazon API Gateway

**REST API Configuration:**
- Regional endpoint for API calls
- Lambda proxy integration
- Request validation
- Usage plans and API keys for agent authentication
- Custom domain with ACM certificate

**WebSocket API Configuration:**
- Real-time progress updates during security tests
- Connection management via Lambda
- Routes: $connect, $disconnect, sendProgress

**Endpoints:**

| Method | Path | Handler | Description |
|--------|------|---------|-------------|
| POST | /auth/login | auth-handler | User login |
| POST | /auth/register | auth-handler | User registration |
| POST | /auth/refresh | auth-handler | Token refresh |
| GET | /organizations | org-handler | List user's organizations |
| POST | /scans | scan-handler | Start discovery scan |
| GET | /scans | scan-handler | List scans |
| GET | /scans/{id} | scan-handler | Get scan details |
| POST | /tests | test-handler | Start security test |
| GET | /tests/{id} | test-handler | Get test status |
| GET | /tests/{id}/findings | findings-handler | Get test findings |
| POST | /reports | report-handler | Generate report |
| GET | /reports/{id} | report-handler | Download report |
| POST | /agents/register | agent-handler | Register on-prem agent |
| POST | /agents/results | agent-handler | Upload agent results |

### Amazon Cognito

**User Pool Configuration:**
- Email/password authentication
- OAuth 2.0 / OIDC support
- GitHub as identity provider (for SSO)
- Custom attributes: organization_id, role
- JWT token expiration: 1 hour access, 30 day refresh

**Identity Pool:**
- Not required (using User Pool tokens directly)

### AWS Lambda

**Function Configuration:**

| Function | Memory | Timeout | Trigger | Description |
|----------|--------|---------|---------|-------------|
| auth-handler | 256 MB | 10s | API Gateway | Authentication operations |
| scan-handler | 256 MB | 10s | API Gateway | Scan CRUD operations |
| test-handler | 256 MB | 10s | API Gateway | Test CRUD operations |
| findings-handler | 256 MB | 10s | API Gateway | Findings queries |
| report-handler | 512 MB | 30s | API Gateway | Report generation initiation |
| agent-handler | 256 MB | 10s | API Gateway | Agent registration, results |
| websocket-handler | 256 MB | 10s | API Gateway WS | WebSocket connection management |
| scan-worker | 512 MB | 5m | SQS | GitHub repository scanning |
| connect-mcp | 256 MB | 30s | Step Functions | MCP connection establishment |
| discover-tools | 256 MB | 30s | Step Functions | Tool enumeration |
| auth-test | 256 MB | 60s | Step Functions | Authentication tests |
| input-validation-test | 512 MB | 2m | Step Functions | Injection tests |
| rate-limit-test | 256 MB | 2m | Step Functions | Rate limiting tests |
| data-exposure-test | 256 MB | 60s | Step Functions | PII/secret detection |
| supply-chain-test | 256 MB | 60s | Step Functions | CVE lookup |
| prompt-injection-test | 256 MB | 60s | Step Functions | Prompt injection tests |
| description-analysis | 256 MB | 30s | Step Functions | Tool description analysis |
| aggregate-results | 512 MB | 30s | Step Functions | Result aggregation, scoring |
| report-generator | 1024 MB | 2m | SQS | PDF/HTML report generation |
| alert-sender | 256 MB | 30s | SQS | Email/notification delivery |

**Lambda Layers:**
- `mcp-client-layer`: Shared MCP protocol client library
- `common-utils-layer`: Shared utilities, database clients

### AWS Step Functions

**SecurityTestWorkflow State Machine:**

```
StartTest
    │
    ▼
ConnectMCP ──── (Error) ──► MarkFailed
    │
    ▼
DiscoverTools
    │
    ▼
UpdateProgress ("Running Level 1...")
    │
    ▼
┌───────────────────────────────────────┐
│         PARALLEL: Level 1 Tests       │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ │
│  │AuthTest │ │InputVal │ │RateLimit│ │
│  └─────────┘ └─────────┘ └─────────┘ │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ │
│  │DataExpo │ │SupplyCh │ │AuthzTest│ │
│  └─────────┘ └─────────┘ └─────────┘ │
└───────────────────────────────────────┘
    │
    ▼
AggregateLevel1
    │
    ▼
Choice: test_level == 2?
    │
    ├── Yes ──►  PARALLEL: Level 2 Tests ──► AggregateAll
    │
    └── No ───► AggregateAll
                    │
                    ▼
               GenerateReport
                    │
                    ▼
               SendAlerts (if critical findings)
                    │
                    ▼
               Complete
```

**State Machine Configuration:**
- Standard workflow (not Express)
- 25,000 state transitions max per execution
- Execution timeout: 30 minutes
- Error handling with retry and catch blocks

### Amazon DynamoDB

**Table Design (Single-Table Pattern):**

**Table: mcp-audit-{env}**

| Entity | PK | SK | Attributes |
|--------|----|----|------------|
| User | USER#{user_id} | PROFILE | email, name, cognito_sub, created_at |
| User-Org | USER#{user_id} | ORG#{org_id} | role, joined_at |
| Organization | ORG#{org_id} | META | name, plan, settings, created_at |
| Scan | ORG#{org_id} | SCAN#{scan_id} | type, status, target, started_at, completed_at, summary |
| DiscoveredMCP | SCAN#{scan_id} | MCP#{mcp_id} | name, source, repo, config_path, risk_level, package_manifest |
| Finding | SCAN#{scan_id} | FINDING#{finding_id} | type, severity, tool, evidence, remediation, status |
| Agent | ORG#{org_id} | AGENT#{agent_id} | name, status, last_seen, api_key_hash |
| APIKey | APIKEY#{key_hash} | META | org_id, agent_id, created_at, expires_at, permissions |

**DiscoveredMCP Entity Detail:**

The DiscoveredMCP entity stores MCPs found during discovery scans, along with metadata needed for security testing:

```json
{
  "PK": "SCAN#abc123",
  "SK": "MCP#postgres-mcp",
  "name": "postgres-mcp",
  "source": "npx @anthropic/postgres-mcp",
  "repo": "apisec-inc/backend",
  "config_path": "mcp.json",
  "risk_level": "high",
  "known": true,
  "registry_id": "postgres-mcp",
  "package_manifest": {
    "type": "npm",
    "path": "package.json",
    "content": "{...package.json content...}",
    "lock_path": "package-lock.json",
    "lock_content": "{...lock file content...}"
  }
}
```

This stored `package_manifest` data is used during security testing for supply chain analysis, eliminating the need to re-fetch from the repository.

**Global Secondary Indexes:**

| GSI Name | PK | SK | Purpose |
|----------|----|----|---------|
| GSI1 | GSI1PK | GSI1SK | User lookup by email |
| GSI2 | status | created_at | Find running scans |
| GSI3 | org_id | severity | Org-wide finding queries |

**Capacity:**
- On-demand capacity mode (pay per request)
- Point-in-time recovery enabled
- TTL on session/temporary data

### Amazon S3

**Buckets:**

| Bucket | Purpose | Lifecycle |
|--------|---------|-----------|
| mcp-audit-{env}-webapp | Static website hosting | None |
| mcp-audit-{env}-reports | Generated reports (PDF, HTML) | 90 day expiration |
| mcp-audit-{env}-exports | JSON/CSV exports | 30 day expiration |
| mcp-audit-{env}-agent-configs | Agent configuration templates | None |

**Configuration:**
- Server-side encryption (SSE-S3)
- Versioning enabled on webapp bucket
- CORS configured for webapp bucket
- Pre-signed URLs for report downloads

### Amazon ElastiCache (Redis)

**Cluster Configuration:**
- Engine: Redis 7.x
- Node type: cache.t3.micro (dev), cache.t3.small (prod)
- Single node (dev), Multi-AZ (prod)
- Encryption in transit and at rest

**Use Cases:**
- WebSocket connection mapping
- Test progress caching
- Rate limiting counters
- Session token blacklist

### Amazon SQS

**Queues:**

| Queue | Purpose | Visibility Timeout | DLQ |
|-------|---------|-------------------|-----|
| mcp-audit-{env}-scan-queue | GitHub scan jobs | 5 minutes | Yes |
| mcp-audit-{env}-report-queue | Report generation jobs | 3 minutes | Yes |
| mcp-audit-{env}-alert-queue | Notification delivery | 30 seconds | Yes |

**Configuration:**
- Standard queues (not FIFO)
- Message retention: 4 days
- Dead-letter queue after 3 failed attempts

### Amazon CloudFront

**Distribution Configuration:**
- Origin: S3 webapp bucket
- SSL certificate: ACM (us-east-1)
- Price class: PriceClass_100 (North America, Europe)
- Cache policy: CachingOptimized for static assets
- Origin request policy: CORS-S3Origin

**Behaviors:**
- Default (*): S3 origin, cached
- /api/*: API Gateway origin, no cache

### AWS WAF

**Web ACL Rules:**
- AWS Managed Rules: Common Rule Set
- AWS Managed Rules: Known Bad Inputs
- Rate limiting: 2000 requests per 5 minutes per IP
- Geographic restrictions: None (global access)

---

## Data Flow Diagrams

### Discovery Scan Flow

```
┌─────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  User   │────►│ API Gateway │────►│ scan-handler│────►│    SQS      │
│(Browser)│     │             │     │  (Lambda)   │     │ scan-queue  │
└─────────┘     └─────────────┘     └─────────────┘     └──────┬──────┘
                                                               │
                     ┌─────────────────────────────────────────┘
                     │
                     ▼
              ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
              │ scan-worker │────►│ GitHub API  │────►│  DynamoDB   │
              │  (Lambda)   │     │             │     │  (Results)  │
              └─────────────┘     └─────────────┘     └─────────────┘
                     │
                     │ Progress updates
                     ▼
              ┌─────────────┐     ┌─────────────┐
              │  WebSocket  │────►│   Browser   │
              │   (APIGW)   │     │             │
              └─────────────┘     └─────────────┘
```

**What scan-worker captures from GitHub:**
1. MCP configuration files (mcp.json, claude_desktop_config.json)
2. Package manifests (package.json, requirements.txt, go.mod)
3. Lock files (package-lock.json, yarn.lock, poetry.lock)
4. Repository metadata (last commit, branch)

All captured data is stored in DynamoDB as DiscoveredMCP entities for use during security testing.

### Discovery to Security Test Data Flow

When a user initiates a security test from discovery results, the system links the test to the discovered MCP data:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DISCOVERY → SECURITY TEST DATA FLOW                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. User selects MCP from discovery results                                 │
│     ┌──────────────────────────────────────────────────────────────────┐   │
│     │  "Test postgres-mcp from apisec-inc/backend"                     │   │
│     │  discovery_id: SCAN#abc123/MCP#postgres-mcp                      │   │
│     └──────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  2. API creates security test with reference to discovery                   │
│     ┌──────────────────────────────────────────────────────────────────┐   │
│     │  POST /tests                                                      │   │
│     │  {                                                                │   │
│     │    "mcp_url": "http://localhost:5432/mcp",                       │   │
│     │    "discovery_ref": "SCAN#abc123/MCP#postgres-mcp",              │   │
│     │    "level": 2                                                     │   │
│     │  }                                                                │   │
│     └──────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  3. During security test, supply-chain-test Lambda fetches stored data     │
│     ┌──────────────────────────────────────────────────────────────────┐   │
│     │  DynamoDB.get(PK="SCAN#abc123", SK="MCP#postgres-mcp")           │   │
│     │  → Returns package_manifest data captured during discovery       │   │
│     └──────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  4. Supply chain analysis uses stored manifest (no GitHub re-fetch)        │
│     ┌──────────────────────────────────────────────────────────────────┐   │
│     │  Parse package.json → Extract dependencies → Query OSV for CVEs  │   │
│     └──────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**URL-Only Test (No Discovery Reference):**
When testing via URL alone, supply chain analysis is marked as "Unable to assess" since no package manifest data is available.

### Security Test Flow

```
┌─────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  User   │────►│ API Gateway │────►│ test-handler│────►│    Step     │
│(Browser)│     │             │     │  (Lambda)   │     │  Functions  │
└─────────┘     └─────────────┘     └─────────────┘     └──────┬──────┘
                                                               │
     ┌─────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Step Functions Workflow                           │
│                                                                         │
│  ConnectMCP ──► DiscoverTools ──► Level1Tests ──► Level2Tests ──► Done │
│      │              │                 │               │            │    │
│      └──────────────┴─────────────────┴───────────────┴────────────┘    │
│                                       │                                  │
│                              (Each step updates)                         │
│                                       │                                  │
└───────────────────────────────────────┼─────────────────────────────────┘
                                        │
                                        ▼
                                 ┌─────────────┐
                                 │    Redis    │
                                 │  (Progress) │
                                 └──────┬──────┘
                                        │
                                        ▼
                                 ┌─────────────┐     ┌─────────────┐
                                 │  WebSocket  │────►│   Browser   │
                                 │   (APIGW)   │     │             │
                                 └─────────────┘     └─────────────┘
```

### On-Prem Agent Flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        Customer Network                                   │
│                                                                          │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐               │
│   │   Agent     │────►│  Internal   │     │  Internal   │               │
│   │  (Docker)   │     │   MCP 1     │     │   MCP 2     │               │
│   └──────┬──────┘     └─────────────┘     └─────────────┘               │
│          │                                                               │
│          │ Tests MCPs locally                                            │
│          │                                                               │
│          │ Results only (sanitized)                                      │
│          │ No MCP data sent                                              │
│          │                                                               │
└──────────┼───────────────────────────────────────────────────────────────┘
           │
           │ HTTPS
           ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                           AWS Cloud                                       │
│                                                                          │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐               │
│   │ API Gateway │────►│agent-handler│────►│  DynamoDB   │               │
│   │/agents/results    │  (Lambda)   │     │             │               │
│   └─────────────┘     └─────────────┘     └─────────────┘               │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Security Architecture

### Authentication Flow

```
┌─────────┐     ┌─────────────┐     ┌─────────────┐
│  User   │────►│   Cognito   │────►│   Return    │
│ (Login) │     │ User Pool   │     │    JWT      │
└─────────┘     └─────────────┘     └─────────────┘
                                           │
                                           ▼
┌─────────┐     ┌─────────────┐     ┌─────────────┐
│  User   │────►│ API Gateway │────►│   Lambda    │
│(API Call)     │(JWT Authorizer)   │  (Handler)  │
└─────────┘     └─────────────┘     └─────────────┘
```

### Agent Authentication

```
┌─────────┐     ┌─────────────┐     ┌─────────────┐
│  Admin  │────►│  Dashboard  │────►│  Generate   │
│         │     │             │     │  API Key    │
└─────────┘     └─────────────┘     └─────────────┘
                                           │
                                           ▼
                                    ┌─────────────┐
                                    │  DynamoDB   │
                                    │(Store Hash) │
                                    └─────────────┘

┌─────────┐     ┌─────────────┐     ┌─────────────┐
│  Agent  │────►│ API Gateway │────►│   Lambda    │
│(API Key │     │(API Key Auth)     │  (Verify)   │
│ Header) │     └─────────────┘     └─────────────┘
└─────────┘
```

### Data Privacy

**What Stays On-Premise (Agent):**
- MCP credentials and authentication tokens
- Actual data returned by MCPs
- Full request/response payloads
- Internal network topology
- Source code

**What Is Sent to Cloud:**
- MCP name (can be anonymized)
- Test results (pass/fail)
- Vulnerability findings (type, severity)
- Sanitized evidence (no actual data values)
- Metadata (timestamps, duration)

### Encryption

| Data | At Rest | In Transit |
|------|---------|------------|
| DynamoDB | SSE-KMS | TLS 1.2+ |
| S3 | SSE-S3 | TLS 1.2+ |
| ElastiCache | Encryption enabled | TLS 1.2+ |
| Secrets Manager | AWS managed key | TLS 1.2+ |
| API traffic | N/A | TLS 1.2+ |

---

## Infrastructure as Code

### CDK Stack Structure

```
infrastructure/
├── bin/
│   └── app.ts                    # CDK app entry point
├── lib/
│   ├── stacks/
│   │   ├── api-stack.ts          # API Gateway, Lambda API handlers
│   │   ├── auth-stack.ts         # Cognito User Pool
│   │   ├── compute-stack.ts      # Lambda functions
│   │   ├── data-stack.ts         # DynamoDB, S3
│   │   ├── workflow-stack.ts     # Step Functions
│   │   ├── messaging-stack.ts    # SQS, SNS, SES
│   │   ├── cache-stack.ts        # ElastiCache
│   │   ├── cdn-stack.ts          # CloudFront, WAF
│   │   └── monitoring-stack.ts   # CloudWatch, X-Ray
│   ├── constructs/
│   │   ├── lambda-function.ts    # Custom Lambda construct
│   │   └── api-endpoint.ts       # Custom API endpoint construct
│   └── config/
│       ├── environments.ts       # Environment configurations
│       └── constants.ts          # Shared constants
├── cdk.json
├── package.json
└── tsconfig.json
```

### Environment Configuration

```typescript
// lib/config/environments.ts

export interface EnvironmentConfig {
  envName: string;
  awsAccount: string;
  awsRegion: string;
  domainName?: string;
  alertEmail?: string;
  logRetentionDays: number;
  enableXRay: boolean;
}

export const environments: Record<string, EnvironmentConfig> = {
  dev: {
    envName: 'dev',
    awsAccount: '123456789012',
    awsRegion: 'us-east-1',
    logRetentionDays: 7,
    enableXRay: true,
  },
  prod: {
    envName: 'prod',
    awsAccount: '123456789012',
    awsRegion: 'us-east-1',
    domainName: 'mcp-audit.apisec.ai',
    alertEmail: 'alerts@apisec.ai',
    logRetentionDays: 90,
    enableXRay: true,
  },
};
```

---

## Project Structure

```
mcp-audit/
├── infrastructure/                 # AWS CDK
│   ├── bin/
│   ├── lib/
│   └── package.json
│
├── lambdas/                        # Lambda function code
│   ├── api/                        # API handlers
│   │   ├── auth/
│   │   ├── scans/
│   │   ├── tests/
│   │   ├── findings/
│   │   ├── reports/
│   │   └── agents/
│   ├── workers/                    # Async workers
│   │   ├── scan-worker/
│   │   ├── report-generator/
│   │   └── alert-sender/
│   ├── step-functions/             # Step Function tasks
│   │   ├── connect-mcp/
│   │   ├── discover-tools/
│   │   ├── tests/
│   │   │   ├── auth-test/
│   │   │   ├── input-validation/
│   │   │   ├── rate-limit/
│   │   │   ├── data-exposure/
│   │   │   ├── supply-chain/
│   │   │   ├── prompt-injection/
│   │   │   ├── description-analysis/
│   │   │   ├── response-injection/
│   │   │   ├── rug-pull/
│   │   │   ├── cross-mcp/
│   │   │   └── context-exhaustion/
│   │   └── aggregate-results/
│   ├── layers/                     # Lambda layers
│   │   ├── mcp-client/
│   │   └── common-utils/
│   └── shared/                     # Shared code
│       ├── mcp_client/
│       ├── db_client/
│       ├── models/
│       └── utils/
│
├── webapp/                         # React frontend
│   ├── src/
│   │   ├── pages/
│   │   ├── components/
│   │   ├── hooks/
│   │   ├── services/
│   │   ├── stores/
│   │   └── utils/
│   ├── public/
│   └── package.json
│
├── cli/                            # CLI tool
│   ├── mcp_audit/
│   │   ├── __init__.py
│   │   ├── cli.py
│   │   ├── client/
│   │   ├── tests/
│   │   └── reporting/
│   ├── setup.py
│   └── requirements.txt
│
├── agent/                          # On-prem agent
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── src/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── scheduler.py
│   │   ├── tester.py
│   │   └── uploader.py
│   └── requirements.txt
│
├── github-action/                  # GitHub Action
│   ├── action.yml
│   ├── Dockerfile
│   └── entrypoint.sh
│
├── tests/                          # Integration tests
│   ├── integration/
│   ├── e2e/
│   └── fixtures/
│
├── docs/                           # Documentation
│   ├── 01-functional-capabilities.md
│   ├── 02-architecture-technical-design.md
│   └── 03-implementation-plan.md
│
├── scripts/                        # Utility scripts
│   ├── deploy-dev.sh
│   ├── deploy-prod.sh
│   └── local-test.sh
│
├── .github/
│   └── workflows/
│       └── ci-cd.yml
│
└── README.md
```

---

## Monitoring and Observability

### CloudWatch Metrics

**Custom Metrics:**
- ScansStarted (Count)
- ScansCompleted (Count)
- ScansFailed (Count)
- TestsStarted (Count)
- TestsCompleted (Count)
- VulnerabilitiesFound (Count, by severity)
- AgentHeartbeats (Count)

**Alarms:**
- Lambda error rate > 5%
- API Gateway 5xx rate > 1%
- Step Function execution failures
- DynamoDB throttling
- SQS dead-letter queue messages

### CloudWatch Logs

**Log Groups:**
- /aws/lambda/mcp-audit-{env}-{function}
- /aws/apigateway/mcp-audit-{env}
- /aws/stepfunctions/mcp-audit-{env}

**Log Retention:**
- Dev: 7 days
- Prod: 90 days

### X-Ray Tracing

- Enabled on all Lambda functions
- Enabled on API Gateway
- Custom subsegments for MCP calls
- Trace sampling: 5% in prod

---

## Cost Estimation

### Monthly Cost Estimate (Development)

| Service | Usage | Estimated Cost |
|---------|-------|----------------|
| Lambda | 100K invocations | $2 |
| API Gateway | 100K requests | $0.35 |
| Step Functions | 5K transitions | $0.13 |
| DynamoDB | On-demand, <1GB | $1 |
| S3 | 10GB storage | $0.23 |
| CloudFront | 50GB transfer | $4.25 |
| ElastiCache | t3.micro | $12 |
| Cognito | <50 MAU | $0 |
| CloudWatch | Logs + metrics | $5 |
| **Total** | | **~$25/month** |

### Monthly Cost Estimate (Production - Medium Traffic)

| Service | Usage | Estimated Cost |
|---------|-------|----------------|
| Lambda | 1M invocations | $20 |
| API Gateway | 1M requests | $3.50 |
| Step Functions | 50K transitions | $1.25 |
| DynamoDB | On-demand, 10GB | $15 |
| S3 | 100GB storage | $2.30 |
| CloudFront | 500GB transfer | $42.50 |
| ElastiCache | t3.small | $24 |
| Cognito | 1000 MAU | $0 |
| CloudWatch | Logs + metrics | $20 |
| WAF | 1M requests | $6 |
| **Total** | | **~$135/month** |

---

## Scalability Considerations

### Current Design Limits

| Component | Limit | Mitigation |
|-----------|-------|------------|
| Lambda concurrent executions | 1000 (default) | Request increase |
| API Gateway requests/sec | 10,000 | Regional scaling |
| DynamoDB | Unlimited (on-demand) | N/A |
| Step Functions | 1M open executions | Execution cleanup |
| S3 | Unlimited | N/A |

### Future Scaling Options

1. **Multi-region deployment** — Deploy to multiple AWS regions for global users
2. **Reserved concurrency** — Guarantee Lambda capacity for critical functions
3. **DynamoDB DAX** — Add caching layer if read-heavy
4. **ElastiCache cluster mode** — Scale Redis horizontally

---

## Disaster Recovery

### Backup Strategy

| Component | Backup Method | Retention | RPO |
|-----------|--------------|-----------|-----|
| DynamoDB | Point-in-time recovery | 35 days | 5 minutes |
| S3 | Versioning + cross-region replication | Indefinite | Near-zero |
| Cognito | N/A (managed) | N/A | N/A |

### Recovery Procedures

1. **DynamoDB** — Restore to point in time via AWS Console or CLI
2. **S3** — Restore from versioned objects or cross-region replica
3. **Lambda/Step Functions** — Redeploy from CDK (code in Git)
4. **Infrastructure** — Full redeploy via CDK

### RTO Targets

| Scenario | RTO |
|----------|-----|
| Single Lambda failure | < 1 minute (auto-retry) |
| DynamoDB table corruption | < 1 hour (PITR restore) |
| Full region failure | < 4 hours (redeploy to new region) |

---

## Summary

This architecture provides a scalable, serverless platform for MCP security testing with:

- **Serverless-first design** — Minimal operational overhead, pay-per-use
- **Event-driven processing** — SQS queues and Step Functions for reliability
- **Real-time updates** — WebSocket for live progress during tests
- **Flexible deployment** — Cloud dashboard + on-prem agents
- **Security by design** — Cognito auth, WAF protection, encryption throughout
- **Observability** — CloudWatch metrics, logs, and X-Ray tracing

The architecture supports growth from initial launch to enterprise scale without significant re-architecture.
