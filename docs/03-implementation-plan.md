# MCP Audit - Implementation Plan

## Overview

This document outlines the implementation plan for the MCP Audit platform. The plan is organized into phases, with each phase delivering incremental, usable functionality. Total estimated duration is 16 weeks.

---

## Phase Summary

| Phase | Duration | Focus | Key Deliverables |
|-------|----------|-------|------------------|
| **Phase 0** | Weeks 1-2 | Foundation | AWS infrastructure, project setup, MCP client library |
| **Phase 1** | Weeks 3-5 | Core Testing | Level 1 security tests (high efficacy) |
| **Phase 2** | Weeks 6-7 | AI-Specific Testing | Level 2 security tests |
| **Phase 3** | Weeks 8-9 | Reporting | Report generation, scorecards, exports |
| **Phase 4** | Weeks 10-12 | Web Application | Full web dashboard with all features |
| **Phase 5** | Weeks 13-14 | Agent & CI/CD | On-prem agent, GitHub Action |
| **Phase 6** | Weeks 15-16 | Polish & Launch | Testing, documentation, launch |

---

## Phase 0: Foundation (Weeks 1-2)

### Objective
Establish the technical foundation: AWS infrastructure, development environment, and core libraries that all other components depend on.

### Week 1: Infrastructure Setup

#### Task 0.1: AWS Environment Setup
- Configure AWS CLI with credentials
- Create IAM user/role for development
- Set up AWS CDK and bootstrap the account
- Create development and production environment configurations
- **Deliverable:** Working CDK environment, ability to deploy stacks

#### Task 0.2: Core Infrastructure Stacks
- Create CDK stack for DynamoDB tables (users, scans, findings)
- Create CDK stack for S3 buckets (reports, exports, webapp)
- Create CDK stack for API Gateway (REST API skeleton)
- Create CDK stack for Cognito User Pool
- **Deliverable:** Deployed base infrastructure in dev environment

#### Task 0.3: Project Structure
- Set up monorepo structure with all directories
- Configure Python virtual environments for Lambdas
- Configure Node.js/TypeScript for CDK and webapp
- Set up shared code structure (Lambda layers)
- Create development scripts (deploy-dev.sh, local-test.sh)
- **Deliverable:** Complete project structure, ready for development

### Week 2: MCP Client Library

#### Task 0.4: MCP Protocol Implementation
- Implement MCP JSON-RPC message formatting
- Implement `initialize` method
- Implement `tools/list` method
- Implement `tools/call` method
- Handle MCP protocol errors
- **Deliverable:** Core MCP protocol library

#### Task 0.5: HTTP Transport
- Implement HTTP client for MCP servers
- Handle SSE (Server-Sent Events) transport
- Implement connection timeout and retry logic
- Implement authentication (API key, Bearer token)
- **Deliverable:** HTTP-based MCP client

#### Task 0.6: Test Framework Foundation
- Create `BaseSecurityTest` abstract class
- Create `TestResult` and `Finding` data models
- Create test registry for discovering and running tests
- Create test runner that executes tests against MCP
- **Deliverable:** Security test framework skeleton

#### Task 0.7: Basic CLI
- Set up Click-based CLI structure
- Implement `mcp-audit test --url <url>` command skeleton
- Implement basic console output formatting
- **Deliverable:** CLI that can connect to an MCP and list tools

### Phase 0 Milestone
- [ ] CDK deploys successfully to dev environment
- [ ] DynamoDB tables, S3 buckets, API Gateway exist
- [ ] MCP client can connect to a test MCP server
- [ ] CLI can invoke `mcp-audit test --url` and show tools
- [ ] All code committed to Git repository

---

## Phase 1: Core Security Tests (Weeks 3-5)

### Objective
Implement Level 1 security tests with highest detection efficacy. Focus on tests that provide clear, actionable results.

### Week 3: Input Validation Tests

#### Task 1.1: SQL Injection Test
- Create SQL injection payload library (20+ payloads)
- Implement payload injection for string parameters
- Implement response analysis for SQL error patterns
- Implement behavioral analysis (timing, different responses)
- Create finding report with evidence and remediation
- **Deliverable:** SQL injection detection for MCP tools

#### Task 1.2: Command Injection Test
- Create command injection payload library (15+ payloads)
- Implement shell metacharacter injection
- Implement response analysis for command execution indicators
- Test common patterns: `;`, `|`, `$()`, backticks
- **Deliverable:** Command injection detection

#### Task 1.3: Path Traversal Test
- Create path traversal payload library (10+ payloads)
- Test directory traversal patterns (`../`, `..\`)
- Analyze responses for file content or error patterns
- Handle different OS path separators
- **Deliverable:** Path traversal detection

#### Task 1.4: Input Validation Lambda
- Package input validation tests as Lambda function
- Integrate with Step Functions workflow
- Handle timeouts and errors gracefully
- Return structured findings
- **Deliverable:** Deployed input-validation-test Lambda

### Week 4: Rate Limiting and Data Exposure Tests

#### Task 1.5: Rate Limiting Test
- Implement configurable request flood (requests/second)
- Measure response times and error rates
- Detect 429 responses and custom throttling
- Calculate rate limit thresholds if present
- Report on absence of rate limiting
- **Deliverable:** Rate limiting detection

#### Task 1.6: Data Exposure Test
- Create PII pattern library (SSN, CC, email, phone)
- Create secret pattern library (API keys, passwords, tokens)
- Implement response scanning with regex patterns
- Implement confidence scoring to reduce false positives
- **Deliverable:** PII and secret detection in responses

#### Task 1.7: Deploy Rate Limit and Data Exposure Lambdas
- Package tests as Lambda functions
- Add to Step Functions workflow
- Test in dev environment
- **Deliverable:** Deployed rate-limit-test and data-exposure-test Lambdas

### Week 5: Authentication and Supply Chain Tests

#### Task 1.8: Authentication Test
- Implement no-credential access test
- Implement invalid token test
- Implement expired token test (if detectable)
- Analyze authentication error responses
- **Deliverable:** Authentication requirement detection

#### Task 1.9: Authorization Test
- Implement ID manipulation tests
- Implement scope boundary tests
- Detect permission bypass opportunities
- **Deliverable:** Basic authorization testing

#### Task 1.10: Supply Chain Test
- Implement package.json parser
- Implement requirements.txt parser
- Integrate with OSV API for CVE lookup
- Check version pinning
- **Deliverable:** Dependency vulnerability detection

#### Task 1.11: Complete Step Functions Workflow
- Create complete SecurityTestWorkflow state machine
- Implement parallel execution of Level 1 tests
- Implement result aggregation
- Add progress updates via Redis/WebSocket
- **Deliverable:** End-to-end Level 1 test workflow

### Phase 1 Milestone
- [ ] All Level 1 tests implemented and deployed
- [ ] Step Functions workflow executes complete Level 1 assessment
- [ ] CLI can run full Level 1 test: `mcp-audit test --url <url> --level 1`
- [ ] Findings include evidence and remediation guidance
- [ ] Tests verified against mock MCP servers

---

## Phase 2: AI-Specific Security Tests (Weeks 6-7)

### Objective
Implement Level 2 tests that address AI-specific security threats unique to MCP integrations.

### Week 6: Prompt Injection and Description Analysis

#### Task 2.1: Tool Description Analysis
- Implement description parsing and analysis
- Create red flag detection (vague, broad, misleading keywords)
- Implement vagueness scoring
- Compare descriptions against actual capabilities
- **Deliverable:** Tool description risk analysis

#### Task 2.2: Prompt Injection Test
- Create prompt injection payload library
- Implement instruction override payloads
- Implement role manipulation payloads
- Analyze MCP responses for compliance indicators
- Identify MCPs that process untrusted content + have actions
- **Deliverable:** Prompt injection risk assessment

#### Task 2.3: Response Injection Detection
- Scan MCP responses for instruction-like patterns
- Detect imperative commands, role assignments
- Detect system message markers
- **Deliverable:** Response injection detection

#### Task 2.4: Deploy Level 2 Test Lambdas (Part 1)
- Package description-analysis Lambda
- Package prompt-injection-test Lambda
- Package response-injection Lambda
- Add to Step Functions workflow
- **Deliverable:** First set of Level 2 tests deployed

### Week 7: Remaining Level 2 Tests

#### Task 2.5: Rug Pull Risk Assessment
- Check version pinning in MCP configuration
- Identify auto-update configurations
- Assess source trustworthiness
- **Deliverable:** Rug pull risk scoring

#### Task 2.6: Cross-MCP Attack Surface Analysis
- Enumerate all MCPs in same environment
- Classify trust levels
- Identify potential attack chains
- Assess isolation boundaries
- **Deliverable:** Cross-MCP risk assessment

#### Task 2.7: Context Exhaustion Test
- Trigger large responses from each tool
- Measure maximum response sizes
- Flag unbounded response capabilities
- **Deliverable:** Context exhaustion risk detection

#### Task 2.8: Complete Level 2 Integration
- Package remaining Level 2 test Lambdas
- Update Step Functions to include Level 2 tests
- Implement conditional Level 2 execution (based on level parameter)
- **Deliverable:** Complete Level 1 + Level 2 test workflow

#### Task 2.9: Result Aggregation and Scoring
- Implement aggregate-results Lambda
- Calculate per-category risk scores
- Calculate overall security score (0-100)
- Generate scorecard data structure
- **Deliverable:** Security scorecard generation

### Phase 2 Milestone
- [ ] All Level 2 tests implemented and deployed
- [ ] CLI can run full test: `mcp-audit test --url <url> --level 2`
- [ ] Scorecard displays all categories with risk levels
- [ ] Complete test workflow executes in < 5 minutes

---

## Phase 3: Reporting (Weeks 8-9)

### Objective
Implement comprehensive reporting capabilities with multiple export formats and automated delivery.

### Week 8: Report Generation

#### Task 3.1: JSON Report Format
- Define JSON schema for security reports
- Include all findings with full detail
- Include scorecard data
- Include test metadata (duration, timestamp)
- **Deliverable:** JSON export format

#### Task 3.2: HTML Report Generation
- Create HTML report template
- Style with embedded CSS (no external dependencies)
- Include interactive scorecard visualization
- Include expandable finding details
- **Deliverable:** HTML report generation

#### Task 3.3: PDF Report Generation
- Set up PDF generation (Puppeteer or similar)
- Generate from HTML template
- Optimize for printing and sharing
- Include executive summary section
- **Deliverable:** PDF report generation

#### Task 3.4: Report Generator Lambda
- Package report generation as Lambda
- Handle SQS trigger from report-queue
- Upload generated reports to S3
- Generate pre-signed URLs for download
- **Deliverable:** Deployed report-generator Lambda

### Week 9: Export and Notifications

#### Task 3.5: Additional Export Formats
- Implement CSV export for findings
- Implement SARIF format for GitHub integration
- Implement JUnit XML for CI/CD integration
- **Deliverable:** CSV, SARIF, JUnit exports

#### Task 3.6: Alert Notifications
- Configure Amazon SES for email
- Create email templates for critical findings
- Implement Slack webhook notifications
- Create alert-sender Lambda
- **Deliverable:** Email and Slack alerting

#### Task 3.7: CLI Reporting
- Add `--format` option (json, html, csv)
- Add `--output` option for file export
- Display scorecard in terminal
- **Deliverable:** CLI reporting capabilities

### Phase 3 Milestone
- [ ] JSON, HTML, PDF, CSV, SARIF, JUnit exports working
- [ ] Email alerts sent for critical findings
- [ ] CLI supports all output formats
- [ ] Reports stored in S3 with download URLs

---

## Phase 4: Web Application (Weeks 10-12)

### Objective
Build the complete web dashboard for browser-based discovery, testing, and reporting.

### Week 10: Authentication and Core UI

#### Task 4.1: React Project Setup
- Initialize React project with Vite
- Configure TypeScript and Tailwind CSS
- Set up React Query for API state
- Create basic layout (header, navigation, footer)
- **Deliverable:** React project foundation

#### Task 4.2: Authentication UI
- Create login page
- Create registration page
- Implement GitHub OAuth flow
- Store and refresh JWT tokens
- Create protected route wrapper
- **Deliverable:** Working authentication flow

#### Task 4.3: Dashboard Page
- Create dashboard with summary metrics
- Display recent scans and tests
- Show vulnerability counts by severity
- Add quick action buttons
- **Deliverable:** Dashboard page

#### Task 4.4: API Integration
- Create API client service
- Implement authentication interceptors
- Handle API errors consistently
- Set up React Query hooks for data fetching
- **Deliverable:** Frontend-backend integration

### Week 11: Discovery and Testing UI

#### Task 4.5: Discovery Page
- Create GitHub connection flow
- Display organization selector
- Show repository scan progress
- Display discovered MCPs with risk indicators
- **Deliverable:** Discovery page

#### Task 4.6: Security Test Page
- Create MCP selector (from discovery or manual URL)
- Create test configuration form (level, auth)
- Implement real-time progress via WebSocket
- Display live findings as they're discovered
- **Deliverable:** Security test page

#### Task 4.7: Results Page
- Display security scorecard visualization
- List all findings with severity badges
- Implement finding detail expansion
- Add filtering and sorting
- **Deliverable:** Results page

### Week 12: Reporting and Polish

#### Task 4.8: Reports Page
- Create report generation form
- Display previous reports with download links
- Implement scheduled report configuration
- **Deliverable:** Reports page

#### Task 4.9: Settings and Profile
- Create organization settings page
- Create user profile page
- Implement API key management for agents
- **Deliverable:** Settings pages

#### Task 4.10: Deploy Frontend
- Configure S3 bucket for static hosting
- Set up CloudFront distribution
- Configure custom domain (if applicable)
- Deploy frontend via CDK
- **Deliverable:** Deployed web application

### Phase 4 Milestone
- [ ] Complete web application deployed
- [ ] Users can sign up, log in, connect GitHub
- [ ] Discovery scans work end-to-end
- [ ] Security tests work with real-time progress
- [ ] Reports can be generated and downloaded

---

## Phase 5: Agent and CI/CD Integration (Weeks 13-14)

### Objective
Enable testing of internal MCPs via on-premise agent and integrate into CI/CD pipelines.

### Week 13: On-Premise Agent

#### Task 5.1: Agent Core
- Create agent configuration file format (YAML)
- Implement configuration parser
- Implement MCP target management
- Share test code with Lambda functions
- **Deliverable:** Agent core functionality

#### Task 5.2: Agent Scheduler
- Implement cron-based scheduling
- Run tests against configured MCPs
- Collect and format results
- **Deliverable:** Scheduled test execution

#### Task 5.3: Agent Cloud Integration
- Implement API key authentication
- Implement result upload to cloud API
- Handle offline/retry scenarios
- Sanitize results before upload (privacy)
- **Deliverable:** Agent-to-cloud communication

#### Task 5.4: Agent Packaging
- Create Dockerfile for agent
- Create docker-compose.yml for easy deployment
- Write agent deployment documentation
- Publish to Docker Hub
- **Deliverable:** Dockerized agent

### Week 14: CI/CD Integration

#### Task 5.5: GitHub Action
- Create action.yml definition
- Create Docker container for action
- Implement inputs (config path, level, fail-on)
- Generate SARIF output for code scanning
- **Deliverable:** GitHub Action

#### Task 5.6: CI/CD Documentation
- Write GitHub Actions usage guide
- Write GitLab CI usage guide
- Create example workflow files
- Document SARIF integration with GitHub Security
- **Deliverable:** CI/CD documentation

#### Task 5.7: Agent Dashboard Integration
- Display registered agents in web dashboard
- Show agent status and last heartbeat
- Display agent-submitted results
- **Deliverable:** Agent management UI

### Phase 5 Milestone
- [ ] Docker agent can test internal MCPs
- [ ] Agent uploads results to cloud dashboard
- [ ] GitHub Action blocks PRs on critical findings
- [ ] Documentation complete for CI/CD integration

---

## Phase 6: Polish and Launch (Weeks 15-16)

### Objective
Finalize the product for launch with comprehensive testing, documentation, and production hardening.

### Week 15: Testing and Quality

#### Task 6.1: Unit Test Coverage
- Achieve >80% code coverage on Lambda functions
- Achieve >70% coverage on CLI
- Achieve >60% coverage on frontend
- **Deliverable:** Comprehensive unit tests

#### Task 6.2: Integration Testing
- Create integration test suite
- Test complete workflows end-to-end
- Test agent upload flow
- Test reporting flow
- **Deliverable:** Integration test suite

#### Task 6.3: Security Review
- Review authentication implementation
- Review authorization checks
- Scan dependencies for vulnerabilities
- Review data handling and privacy
- **Deliverable:** Security review report

#### Task 6.4: Performance Testing
- Load test API endpoints
- Verify Step Functions handle concurrent executions
- Test large result sets
- **Deliverable:** Performance validation

### Week 16: Documentation and Launch

#### Task 6.5: User Documentation
- Write getting started guide
- Write CLI reference documentation
- Write API reference documentation
- Create video walkthrough
- **Deliverable:** User documentation

#### Task 6.6: Operational Documentation
- Write runbook for common issues
- Document monitoring and alerting
- Document backup and recovery procedures
- **Deliverable:** Operational runbooks

#### Task 6.7: Production Deployment
- Deploy to production AWS environment
- Configure production domain
- Enable production monitoring and alerting
- Verify all features in production
- **Deliverable:** Production deployment

#### Task 6.8: Launch Activities
- Publish CLI to PyPI
- Publish GitHub Action to marketplace
- Publish Docker agent to Docker Hub
- Announce on relevant channels
- **Deliverable:** Public launch

### Phase 6 Milestone
- [ ] All tests passing with target coverage
- [ ] Documentation complete and published
- [ ] Production environment stable
- [ ] CLI, GitHub Action, and Docker agent published
- [ ] Product launched

---

## Risk Register

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| MCP protocol variations | Medium | High | Test against multiple MCP implementations early |
| False positive rate too high | Medium | Medium | Implement confidence scoring, allow tuning |
| Lambda timeout on complex tests | Low | Medium | Break into smaller steps, use Step Functions |
| Rate limiting by GitHub API | Medium | Low | Implement backoff, cache results |
| CORS issues with browser MCP testing | High | Medium | Clearly document HTTP MCP requirements |
| Low user adoption | Medium | High | Focus on clear value prop, easy onboarding |

---

## Dependencies

| Dependency | Type | Required By |
|------------|------|-------------|
| AWS Account | External | Phase 0, Day 1 |
| GitHub OAuth App | External | Phase 4 (OAuth) |
| Domain name | External | Phase 4 (optional) |
| Docker Hub account | External | Phase 5 (agent) |
| PyPI account | External | Phase 6 (CLI) |
| Test MCP servers | Internal | Phase 1 onwards |

---

## Success Criteria

### MVP (End of Phase 4)
- Users can sign up and connect GitHub
- Discovery scan finds MCPs in repositories
- Security test runs Level 1 and Level 2 assessments
- Reports generated in multiple formats
- < 10% false positive rate on high-confidence tests

### Full Launch (End of Phase 6)
- On-premise agent works for internal MCPs
- GitHub Action integrates into CI/CD
- Documentation enables self-service adoption
- Production system stable with monitoring
- At least 3 external beta users validated

---

## Resource Requirements

### Development Team
- 1 Full-stack developer (primary)
- 1 Security engineer (part-time, test design)
- 1 DevOps engineer (part-time, infrastructure)

### Infrastructure
- AWS account with appropriate limits
- Development machines with Docker
- Test MCP servers for validation

### Tools
- GitHub repository
- CI/CD pipeline (GitHub Actions)
- Issue tracking (GitHub Issues)

---

## Timeline Summary

```
Week 1-2:   ████████████████████  Phase 0: Foundation
Week 3-5:   ██████████████████████████████  Phase 1: Core Tests
Week 6-7:   ████████████████████  Phase 2: AI-Specific Tests
Week 8-9:   ████████████████████  Phase 3: Reporting
Week 10-12: ██████████████████████████████  Phase 4: Web Application
Week 13-14: ████████████████████  Phase 5: Agent & CI/CD
Week 15-16: ████████████████████  Phase 6: Polish & Launch
            │                                               │
            └───────────────────────────────────────────────┘
                              16 Weeks Total
```

---

## Appendix: Task Checklist

### Phase 0 Tasks
- [ ] 0.1 AWS Environment Setup
- [ ] 0.2 Core Infrastructure Stacks
- [ ] 0.3 Project Structure
- [ ] 0.4 MCP Protocol Implementation
- [ ] 0.5 HTTP Transport
- [ ] 0.6 Test Framework Foundation
- [ ] 0.7 Basic CLI

### Phase 1 Tasks
- [ ] 1.1 SQL Injection Test
- [ ] 1.2 Command Injection Test
- [ ] 1.3 Path Traversal Test
- [ ] 1.4 Input Validation Lambda
- [ ] 1.5 Rate Limiting Test
- [ ] 1.6 Data Exposure Test
- [ ] 1.7 Deploy Rate Limit and Data Exposure Lambdas
- [ ] 1.8 Authentication Test
- [ ] 1.9 Authorization Test
- [ ] 1.10 Supply Chain Test
- [ ] 1.11 Complete Step Functions Workflow

### Phase 2 Tasks
- [ ] 2.1 Tool Description Analysis
- [ ] 2.2 Prompt Injection Test
- [ ] 2.3 Response Injection Detection
- [ ] 2.4 Deploy Level 2 Test Lambdas (Part 1)
- [ ] 2.5 Rug Pull Risk Assessment
- [ ] 2.6 Cross-MCP Attack Surface Analysis
- [ ] 2.7 Context Exhaustion Test
- [ ] 2.8 Complete Level 2 Integration
- [ ] 2.9 Result Aggregation and Scoring

### Phase 3 Tasks
- [ ] 3.1 JSON Report Format
- [ ] 3.2 HTML Report Generation
- [ ] 3.3 PDF Report Generation
- [ ] 3.4 Report Generator Lambda
- [ ] 3.5 Additional Export Formats
- [ ] 3.6 Alert Notifications
- [ ] 3.7 CLI Reporting

### Phase 4 Tasks
- [ ] 4.1 React Project Setup
- [ ] 4.2 Authentication UI
- [ ] 4.3 Dashboard Page
- [ ] 4.4 API Integration
- [ ] 4.5 Discovery Page
- [ ] 4.6 Security Test Page
- [ ] 4.7 Results Page
- [ ] 4.8 Reports Page
- [ ] 4.9 Settings and Profile
- [ ] 4.10 Deploy Frontend

### Phase 5 Tasks
- [ ] 5.1 Agent Core
- [ ] 5.2 Agent Scheduler
- [ ] 5.3 Agent Cloud Integration
- [ ] 5.4 Agent Packaging
- [ ] 5.5 GitHub Action
- [ ] 5.6 CI/CD Documentation
- [ ] 5.7 Agent Dashboard Integration

### Phase 6 Tasks
- [ ] 6.1 Unit Test Coverage
- [ ] 6.2 Integration Testing
- [ ] 6.3 Security Review
- [ ] 6.4 Performance Testing
- [ ] 6.5 User Documentation
- [ ] 6.6 Operational Documentation
- [ ] 6.7 Production Deployment
- [ ] 6.8 Launch Activities
