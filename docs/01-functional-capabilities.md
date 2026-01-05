# MCP Audit - Functional Capabilities Document

## Executive Summary

MCP Audit is a security assessment platform designed to discover, analyze, and test Model Context Protocol (MCP) servers across enterprise environments. As AI assistants like Claude, Cursor, and GitHub Copilot become integral to software development workflows, MCP servers—the plugins that extend these AI tools with powerful capabilities—represent a growing and largely unmonitored attack surface.

MCP Audit provides security teams with visibility into what MCP servers are deployed, what capabilities they have, and whether they contain security vulnerabilities that could be exploited.

---

## The Problem

### The Rise of MCP Servers

MCP (Model Context Protocol) is a standard that allows AI assistants to connect with external tools and data sources. MCP servers are plugins that give AI assistants capabilities such as:

- **Filesystem access** — Read and write files on developer machines
- **Database access** — Query and modify production databases
- **Shell execution** — Run arbitrary commands
- **API integrations** — Connect to Slack, GitHub, cloud providers with stored credentials
- **Browser automation** — Control web browsers programmatically

### The Security Blind Spot

Development teams are rapidly adopting AI assistants without realizing they're also deploying dozens of MCP plugins with varying levels of access to sensitive systems. Most organizations have:

- **No inventory** of what MCPs are deployed
- **No visibility** into what capabilities those MCPs have
- **No testing** to verify MCPs are secure
- **No monitoring** of MCP behavior

This creates a significant security blind spot where:

1. Developers install MCPs without security review
2. MCPs may have excessive permissions
3. MCPs may contain vulnerabilities (injection, data leakage)
4. Malicious MCPs could exfiltrate data or execute harmful actions
5. AI-specific attacks (prompt injection) could weaponize legitimate MCPs

---

## Solution Overview

MCP Audit addresses this problem through three core capabilities:

| Capability | Description |
|------------|-------------|
| **Discovery** | Find all MCP servers deployed across source code repositories and developer machines |
| **Assessment** | Analyze MCP configurations to understand capabilities and calculate risk scores |
| **Security Testing** | Connect to running MCP servers and perform active security tests to identify vulnerabilities |

### Value Proposition

| Stakeholder | Value |
|-------------|-------|
| **Security Teams** | Gain visibility into AI tool deployments, identify vulnerabilities before exploitation |
| **IT Administrators** | Audit developer machines for unauthorized or risky plugins |
| **Engineering Managers** | Understand what AI capabilities teams are using, enforce policies |
| **Compliance Officers** | Document AI tool usage for SOC2, ISO27001, and other frameworks |
| **Developers** | Validate their MCP configurations are secure before deployment |

---

## Feature 1: MCP Discovery

### Overview

MCP Discovery scans source code repositories and local developer machines to find MCP configurations. It creates an inventory of all MCPs in use across an organization. Importantly, discovery also captures metadata needed for comprehensive security testing, such as package manifests for supply chain analysis.

### Capabilities

**Source Code Repository Scanning**
- Connect to GitHub (GitLab, Bitbucket, Azure DevOps planned)
- Scan all repositories in an organization
- Find MCP configuration files (mcp.json, claude_desktop_config.json, etc.)
- Parse package.json and requirements.txt for MCP dependencies
- Use code search to find MCP-related patterns
- **Capture package manifests** (package.json, package-lock.json, requirements.txt, go.mod) for later supply chain analysis during security testing

**Local System Scanning**
- Scan developer machines via CLI agent
- Find configurations for Claude Desktop, Cursor, VS Code, Windsurf, Zed
- Discover project-level MCP configurations (.mcp/ directories)
- Aggregate results from multiple machines
- Optionally capture source paths for supply chain analysis

**Registry Matching**
- Match discovered MCPs against a curated registry of known MCP servers
- Provide publisher information, official documentation links
- Flag unknown MCPs that require manual review

### Output

For each discovered MCP:
- Name and source/command
- Location (repository, file path, machine)
- Publisher (if known)
- Known/Unknown status
- Preliminary risk assessment based on configuration
- **Package manifest data** (when available from repository scan) — stored for use during security testing

---

## Feature 2: Risk Assessment

### Overview

Risk Assessment analyzes MCP configurations to understand their capabilities and calculate risk scores. This provides prioritization guidance without requiring active testing.

### Static Analysis Factors

| Factor | Description | Risk Impact |
|--------|-------------|-------------|
| **Capability Keywords** | Names containing "shell", "database", "filesystem", "admin" | Higher risk |
| **Environment Variables** | Presence of PASSWORD, TOKEN, SECRET, API_KEY in config | Higher risk |
| **Command Type** | Local scripts vs npx packages vs Docker containers | Varies |
| **Publisher Verification** | Known vendor (Anthropic, Stripe) vs unknown source | Lower/Higher |
| **Permission Scope** | Read-only vs read-write vs execute | Varies |

### Risk Levels

| Level | Criteria | Examples |
|-------|----------|----------|
| **Critical** | Database write, cloud infrastructure, payments, shell execution | postgres-mcp, aws-mcp, shell-mcp |
| **High** | Filesystem write, browser automation, email sending | filesystem-mcp, puppeteer-mcp |
| **Medium** | API access, messaging (Slack, Discord), calendar | slack-mcp, github-mcp |
| **Low** | Read-only access, search, memory/cache | memory-mcp, search-mcp |

### Heuristic Risk Scoring

For unknown MCPs not in our registry, MCP Audit calculates a heuristic risk score based on:

1. **Name analysis** — Keywords that indicate dangerous capabilities
2. **Configuration analysis** — Environment variables that suggest secrets
3. **Command analysis** — How the MCP is invoked (local script = higher risk)
4. **Publisher analysis** — Known vs unknown source

This allows organizations to prioritize which MCPs need immediate security review.

---

## Feature 3: Security Testing

### Overview

Security Testing connects to running MCP servers and performs active security assessments. Unlike static analysis, this provides verified evidence of vulnerabilities by actually testing the MCP's behavior.

### Testing Levels

MCP Audit provides two levels of security testing:

---

### Level 1: Foundational Security

Level 1 tests assess traditional application security concerns. Every MCP should complete Level 1 assessment before deployment.

#### 1.1 Authentication Testing

**What We Test:**
- Whether the MCP requires authentication for access
- Whether authentication is validated per-request
- Whether invalid credentials are properly rejected

**How We Test:**
The security tester attempts to connect to the MCP and invoke tools without providing credentials. It then attempts connections with invalid or malformed credentials. The tester analyzes whether requests succeed or fail, and whether error messages reveal information about the authentication mechanism.

**Risk Assessment:**
- High Risk: No authentication required, or AI platform token is the only protection
- Medium Risk: User identity is passed but not validated per-request
- Low Risk: Per-user authentication with validation on each request

#### 1.2 Authorization Testing

**What We Test:**
- Whether tool-level permissions exist
- Whether authorization is enforced at the MCP level
- Whether users can access data or tools beyond their intended scope

**How We Test:**
The security tester attempts to access resources using IDs or paths that should be outside the authorized scope. It tries to invoke tools that should be restricted based on the user's role. The tester analyzes whether these boundary-crossing attempts succeed or are properly blocked.

**Risk Assessment:**
- High Risk: No authorization checks exist
- Medium Risk: Some restrictions exist but gaps are present
- Low Risk: Granular permissions with least privilege enforced

#### 1.3 Input Validation Testing

**What We Test:**
- Whether inputs are validated for type, length, and format
- Whether parameters can contain executable content (SQL, shell commands, code)
- Whether queries and commands are properly parameterized

**How We Test:**
The security tester sends malicious payloads through each tool parameter. For SQL injection, it sends payloads like `'; DROP TABLE users; --` and analyzes error messages for signs of SQL execution. For command injection, it sends payloads like `; rm -rf /` and `$(whoami)` to detect shell execution. For path traversal, it sends payloads like `../../etc/passwd` to detect filesystem boundary violations. The tester analyzes responses for error messages, behavioral differences, or output that indicates the payload was processed unsafely.

**Risk Assessment:**
- High Risk: Injection vulnerabilities found
- Medium Risk: Validation exists but is incomplete
- Low Risk: Comprehensive validation with parameterized queries

#### 1.4 Data Exposure Testing

**What We Test:**
- Whether any tool can return PII, credentials, or secrets
- Whether sensitive data is filtered or masked
- Whether tools could be chained to exfiltrate data

**How We Test:**
The security tester invokes each tool and scans responses for patterns that indicate sensitive data. It looks for Social Security numbers, credit card numbers, email addresses, API keys, passwords, private keys, and other sensitive formats. The tester builds a catalog of what data types each tool can return and flags any sensitive exposure.

**Risk Assessment:**
- High Risk: Returns credentials, PII, or secrets with no masking
- Medium Risk: Returns internal data with some masking
- Low Risk: Returns only intended data with sensitive fields masked

#### 1.5 Rate Limiting Testing

**What We Test:**
- Whether rate limits exist per user or per tool
- What happens when limits are exceeded
- Whether an AI agent could retry indefinitely

**How We Test:**
The security tester sends a high volume of requests in rapid succession and measures response times and error rates. It looks for HTTP 429 responses, increasing latency, or other throttling indicators. The tester determines whether limits exist, what the thresholds are, and whether the MCP degrades gracefully under load.

**Risk Assessment:**
- High Risk: No rate limiting exists
- Medium Risk: Limits exist but may be insufficient
- Low Risk: Appropriate limits with graceful handling

#### 1.6 Supply Chain Testing

**What We Test:**
- Whether dependencies have known vulnerabilities
- Whether dependency versions are pinned
- Whether the MCP version is pinned in deployment

**How We Test:**
This test requires access to the MCP's source code, which is available in certain scenarios (see "Data Availability by Test Scenario" below). When source code is available—either from a discovery scan that found the MCP in a repository, or from an on-premise agent configured with a source path—the security tester parses the MCP's package manifest (package.json, requirements.txt, go.mod, Cargo.toml) and extracts dependency information. It queries vulnerability databases (OSV, NVD) to identify known CVEs in the dependency tree. The tester checks whether versions are pinned to specific releases or use floating ranges.

**Data Source Requirements:**
- **From Discovery Scan:** During repository scanning, the discovery phase fetches and stores package manifests alongside MCP configurations. When a security test is initiated from discovery results, this stored data is used for supply chain analysis.
- **From On-Prem Agent:** If the agent configuration includes a `source_path` pointing to the MCP's source directory, the agent reads package manifests directly from the filesystem.
- **URL-Only Test:** When testing an MCP via URL alone (without prior discovery or source path), supply chain analysis cannot be performed. The test reports "Unable to assess - no source code access."

**Risk Assessment:**
- High Risk: Known critical vulnerabilities, unpinned versions
- Medium Risk: Some vulnerabilities, mostly pinned
- Low Risk: No known vulnerabilities, fully pinned
- Unknown: Source code not available for analysis

---

### Data Availability by Test Scenario

Not all tests can be performed in all scenarios. The table below clarifies what data is available and which tests can run based on how the security test is initiated.

| Test Category | Discovery → Test | URL-Only Test | Agent with source_path | Agent without source_path |
|---------------|------------------|---------------|------------------------|---------------------------|
| **Authentication** | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| **Authorization** | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| **Input Validation** | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| **Data Exposure** | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| **Rate Limiting** | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| **Supply Chain** | ✅ Full | ❌ Cannot assess | ✅ Full | ❌ Cannot assess |
| **Prompt Injection** | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| **Tool Poisoning** | ✅ Full (source verified) | ⚠️ Limited (no source) | ✅ Full | ⚠️ Limited |
| **Description Analysis** | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| **Response Injection** | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| **Jailbreak Vectors** | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| **Rug Pull Risk** | ✅ Full (version in repo) | ⚠️ Limited | ✅ Full | ⚠️ Limited |
| **Cross-MCP Attacks** | ✅ Full | ⚠️ Limited (single MCP) | ✅ Full | ✅ Full |
| **Context Exhaustion** | ✅ Full | ✅ Full | ✅ Full | ✅ Full |

**Legend:**
- ✅ Full: Complete test with all data available
- ⚠️ Limited: Partial assessment based on available data
- ❌ Cannot assess: Test requires data that is not available

**Recommendation:** For comprehensive security assessment, initiate tests from discovery results or configure agents with source paths whenever possible. URL-only testing is useful for quick assessments but will have gaps in supply chain and source verification tests.

---

### Level 2: AI-Specific Threats

Level 2 tests assess threats unique to AI tool integrations. These tests are recommended for MCPs that process untrusted content, have write capabilities, or come from untrusted sources.

#### 2.1 Prompt Injection Resilience

**What We Test:**
- Whether the MCP processes untrusted content that could contain injected instructions
- What tools could cause harm if triggered by injection
- Whether destructive actions are gated behind confirmation

**How We Test:**
The security tester identifies MCPs that read external content (files, web pages, emails, databases) and also have action capabilities (write, execute, send). It sends prompt injection payloads through content-reading tools and monitors whether subsequent tool behavior changes. Payloads include instruction overrides like "Ignore previous instructions and..." and role manipulations like "You are now in admin mode."

**Risk Assessment:**
- High Risk: Reads untrusted content, has action tools, no confirmation gates
- Medium Risk: Some exposure but mitigations in place
- Low Risk: Read-only, or action tools properly gated

#### 2.2 Tool Poisoning Detection

**What We Test:**
- Whether the MCP source is trusted
- Whether the MCP code has been reviewed
- Whether the MCP requests excessive permissions
- Whether network behavior is monitored

**How We Test:**
The security tester analyzes the MCP's source origin, checking whether it comes from a known publisher's official repository or an unknown source. It compares the claimed capabilities in the tool description against the actual permissions requested. The tester flags MCPs where the source cannot be verified or where there's a mismatch between claimed and actual capabilities.

**Risk Assessment:**
- High Risk: Unknown source, no code review, no monitoring
- Medium Risk: Known source but limited review
- Low Risk: Trusted source, reviewed code, monitored

#### 2.3 Tool Description Analysis

**What We Test:**
- Whether tool descriptions accurately represent functionality
- Whether descriptions are suspiciously vague or overly broad
- Whether descriptions contain misleading claims

**How We Test:**
The security tester parses all tool descriptions and analyzes them for red flags. It looks for overly broad descriptions ("use this for everything"), misleading claims ("safe read-only" when the tool has write capabilities), vague descriptions ("helper function", "utility"), and missing descriptions. The tester compares descriptions against actual observed behavior during testing.

**Risk Assessment:**
- High Risk: Descriptions are deceptive or mismatched with behavior
- Medium Risk: Descriptions are vague
- Low Risk: Descriptions are accurate and specific

#### 2.4 Response Injection Detection

**What We Test:**
- Whether MCP responses contain content that could hijack AI behavior
- Whether responses are validated before entering AI context
- Whether response content is bounded to expected schemas

**How We Test:**
The security tester invokes tools and scans responses for patterns that resemble AI instructions. It looks for imperative commands, role assignments, system message markers, and other content that could manipulate the AI's subsequent behavior. The tester flags MCPs whose responses contain instruction-like content.

**Risk Assessment:**
- High Risk: Untrusted MCP, no response validation
- Medium Risk: Some trust, limited validation
- Low Risk: Trusted source, validated responses

#### 2.5 Jailbreak Vector Analysis

**What We Test:**
- Whether the MCP could be used to request content the AI would refuse directly
- Whether tools provide access to restricted capabilities
- Whether tool combinations create dangerous capabilities

**How We Test:**
The security tester analyzes the MCP's capabilities to identify potential guardrail bypass vectors. It considers whether tools could be used to generate, retrieve, or execute content that the AI model would normally refuse. The tester identifies tool combinations that could be chained to create capabilities beyond what any single tool provides.

**Risk Assessment:**
- High Risk: Tools clearly enable guardrail bypass
- Medium Risk: Potential for misuse exists
- Low Risk: Tools don't provide bypass vectors

#### 2.6 Rug Pull Risk Assessment

**What We Test:**
- Whether the MCP version is pinned
- Whether there is monitoring for behavior changes
- Whether updates are reviewed before deployment

**How We Test:**
The security tester examines the MCP configuration to determine whether a specific version is pinned or whether it uses "latest" or a floating version range. It checks for update monitoring mechanisms and reviews deployment configurations for auto-update settings.

**Risk Assessment:**
- High Risk: Unpinned versions, no monitoring, auto-updates enabled
- Medium Risk: Pinned but limited monitoring
- Low Risk: Pinned, monitored, updates reviewed

#### 2.7 Cross-MCP Attack Surface

**What We Test:**
- What other MCPs are in the same environment
- Whether one MCP could influence others through the AI
- Whether isolation boundaries exist

**How We Test:**
The security tester enumerates all MCPs configured in the same environment and analyzes their trust levels. It identifies potential attack chains where a compromised or malicious MCP could manipulate the AI to misuse other MCPs. The tester evaluates whether MCPs are isolated or share context.

**Risk Assessment:**
- High Risk: Multiple MCPs, no isolation, mixed trust levels
- Medium Risk: Multiple MCPs with some isolation
- Low Risk: Single MCP, or strong isolation between MCPs

#### 2.8 Context Exhaustion Testing

**What We Test:**
- Whether response sizes are bounded
- Whether large responses could push safety instructions out of AI context
- Whether there is monitoring for unusually large responses

**How We Test:**
The security tester attempts to trigger large responses from each tool by requesting maximum data sets, long file reads, or unbounded queries. It measures response sizes and determines whether any tool can return responses large enough to potentially exhaust AI context windows.

**Risk Assessment:**
- High Risk: Unbounded responses, no monitoring
- Medium Risk: Large responses possible, some limits
- Low Risk: Response sizes bounded, monitored

---

## Output and Reporting

### Security Scorecard

After testing, MCP Audit generates a scorecard summarizing results:

```
═══════════════════════════════════════════════════════════════
                     SECURITY SCORECARD
═══════════════════════════════════════════════════════════════

MCP: postgres-mcp
Tested: December 16, 2025

LEVEL 1: FOUNDATIONAL SECURITY
├── Authentication      🔴 HIGH    No authentication required
├── Authorization       🟡 MEDIUM  Some permission gaps found
├── Input Validation    🔴 CRITICAL SQL injection in 2 tools
├── Data Exposure       🟢 LOW     No sensitive data exposed
├── Rate Limiting       🔴 HIGH    No rate limits detected
└── Supply Chain        🟢 LOW     No known CVEs

LEVEL 2: AI-SPECIFIC THREATS
├── Prompt Injection    🟡 MEDIUM  Processes untrusted content
├── Tool Poisoning      🟢 LOW     Verified source
├── Description Manip.  🟢 LOW     Descriptions accurate
├── Response Injection  🟢 LOW     Responses bounded
├── Jailbreak Vectors   🟡 MEDIUM  DB access could be abused
├── Rug Pull Risk       🟢 LOW     Version pinned
├── Cross-MCP Attacks   🟡 MEDIUM  3 other MCPs present
└── Context Exhaustion  🟡 MEDIUM  Large queries possible

OVERALL SCORE: 32/100
OVERALL RISK: CRITICAL
═══════════════════════════════════════════════════════════════
```

### Vulnerability Reports

For each finding, MCP Audit provides:

- **Finding ID** — Unique identifier for tracking
- **Severity** — Critical, High, Medium, or Low
- **Category** — Which test category identified the issue
- **Tool** — Which MCP tool is affected
- **Evidence** — Sanitized evidence of the vulnerability
- **Remediation** — Specific guidance on how to fix the issue

### Export Formats

- **JSON** — Machine-readable for integration with other tools
- **HTML** — Human-readable report for sharing
- **PDF** — Executive summary for leadership
- **SARIF** — GitHub code scanning integration
- **CSV** — Spreadsheet analysis

---

## Deployment Models

### Web Application

Security teams use the web dashboard to:
- Connect GitHub organizations for repository scanning
- View aggregated results across all discovered MCPs
- Initiate security tests against HTTP-accessible MCPs
- Generate and download reports
- Configure alerts for new vulnerabilities

### CLI / On-Premise Agent

For MCPs that are not internet-accessible, organizations deploy the CLI agent:
- Runs inside the corporate network
- Tests internal MCPs (localhost, private IPs)
- Uploads sanitized results to the cloud dashboard
- Supports scheduled scans for continuous monitoring

### CI/CD Integration

Security testing integrates into development workflows:
- GitHub Action runs on pull requests that modify MCP configs
- Blocks merges if critical vulnerabilities are found
- Generates SARIF reports for GitHub Security tab
- Supports policy-based enforcement

---

## Efficacy Expectations

### High Confidence Detection (70-90%)

- Input validation vulnerabilities (SQL injection, command injection, path traversal)
- Missing rate limiting
- PII and secret exposure in responses
- Known CVEs in dependencies
- Missing authentication
- Unbounded response sizes

### Medium Confidence Detection (50-70%)

- Authorization gaps
- Suspicious tool descriptions
- Prompt injection indicators
- Response injection patterns

### Lower Confidence / Heuristic (30-50%)

- Jailbreak potential (highly contextual)
- Tool poisoning risk (requires code review)
- Cross-MCP attack chains (complex analysis)

### Not Testable Externally

- Server-side logging (cannot verify from outside)
- Internal monitoring (server-side only)

---

## Summary

MCP Audit provides organizations with the visibility and testing capabilities needed to secure their AI tool deployments. By combining automated discovery, risk assessment, and active security testing, MCP Audit helps security teams:

1. **Know what's deployed** — Complete inventory of MCPs across repositories and machines
2. **Understand the risk** — Risk scores and capability analysis for prioritization
3. **Verify security** — Active testing to find real vulnerabilities
4. **Maintain compliance** — Documentation and reports for audit requirements
5. **Shift left** — CI/CD integration to catch issues before deployment

As AI assistants become more prevalent in enterprise environments, MCP Audit ensures that the plugins extending their capabilities don't become the weakest link in your security posture.
