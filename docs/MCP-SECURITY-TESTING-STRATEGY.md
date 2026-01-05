# MCP Security Testing Strategy
## A Comprehensive Analysis for Enterprise Security Teams

**Version:** 1.0
**Date:** December 2024
**Author:** APIsec Inc.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Understanding MCP Architecture](#understanding-mcp-architecture)
3. [How MCPs Are Used in Enterprises](#how-mcps-are-used-in-enterprises)
4. [MCP Attack Surface & Threat Model](#mcp-attack-surface--threat-model)
5. [MCP vs API Security: Key Differences](#mcp-vs-api-security-key-differences)
6. [What Makes Sense to Test](#what-makes-sense-to-test)
7. [What Does NOT Apply to MCP Testing](#what-does-not-apply-to-mcp-testing)
8. [Testing Methodology by Phase](#testing-methodology-by-phase)
9. [Recommendations](#recommendations)

---

## Executive Summary

The Model Context Protocol (MCP) is an open standard introduced by Anthropic in November 2024 that standardizes how AI systems connect to external tools, data sources, and services. Within one year, MCP has achieved industry-wide adoption with backing from OpenAI, Google, Microsoft, AWS, and governance under the Linux Foundation.

**Key Statistics (as of December 2024):**
- 8M+ MCP server downloads (up from 100K in Nov 2024)
- 5,800+ MCP servers available
- 300+ MCP clients
- 90% of organizations predicted to use MCP by end of 2025
- Major deployments at Block, Bloomberg, Amazon, Fortune 500 companies

**The Security Challenge:**

As one widely-shared article noted, "the S in MCP stands for security." Research shows:
- 43% of tested MCP implementations contain command injection flaws
- 30% permit unrestricted URL fetching
- 492 publicly exposed MCP servers identified as vulnerable
- CVE-2025-6514 (mcp-remote) compromised 437,000+ developer environments

This document provides a framework for understanding what security testing is meaningful for MCPs, how it differs from traditional API security testing, and what enterprises should prioritize.

---

## Understanding MCP Architecture

### What is MCP?

MCP is like "USB-C for AI applications" - a standardized protocol for connecting AI models to external capabilities. It replaces the N×M integration problem (every AI client needing custom integration with every tool) with a universal protocol.

### Core Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        MCP ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│   ┌──────────────┐         ┌──────────────┐                      │
│   │  MCP Host    │         │  MCP Host    │                      │
│   │ (Claude,     │         │ (Cursor,     │                      │
│   │  ChatGPT)    │         │  VS Code)    │                      │
│   └──────┬───────┘         └──────┬───────┘                      │
│          │                        │                               │
│          └────────────┬───────────┘                               │
│                       │                                           │
│                       ▼                                           │
│              ┌────────────────┐                                   │
│              │   MCP Client   │  (Protocol handler)               │
│              └────────┬───────┘                                   │
│                       │                                           │
│         ┌─────────────┼─────────────┐                            │
│         │             │             │                             │
│         ▼             ▼             ▼                             │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐                       │
│   │MCP Server│  │MCP Server│  │MCP Server│                       │
│   │(GitHub)  │  │(Postgres)│  │(Slack)   │                       │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘                       │
│        │             │             │                              │
│        ▼             ▼             ▼                              │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐                       │
│   │ GitHub   │  │ Database │  │  Slack   │                       │
│   │   API    │  │          │  │   API    │                       │
│   └──────────┘  └──────────┘  └──────────┘                       │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Role | Security Relevance |
|-----------|------|-------------------|
| **MCP Host** | Application running the AI (Claude Desktop, Cursor, IDEs) | Trust boundary - what the user interacts with |
| **MCP Client** | Protocol handler maintaining connections to servers | Manages connections, token handling |
| **MCP Server** | Exposes specific capabilities (tools, resources, prompts) | Primary attack surface - executes operations |
| **Tools** | Functions the LLM can invoke (e.g., `read_file`, `query_db`) | Define what actions are possible |
| **Resources** | Data the LLM can access (files, database records) | Define what data is exposed |
| **Prompts** | Pre-defined prompt templates | Can contain hidden instructions |

### Transport Mechanisms

| Transport | Description | Security Considerations |
|-----------|-------------|------------------------|
| **stdio** | Local process communication | No network exposure, but local process risks |
| **HTTP/SSE** | Remote server via HTTP + Server-Sent Events | Network exposure, requires auth, HTTPS mandatory |
| **WebSocket** | Bidirectional remote communication | Persistent connections, session management |

### How MCP Differs from Traditional APIs

```
TRADITIONAL API                          MCP
─────────────────────────────────────────────────────────────────
User → App → API → Backend               User → AI Agent → MCP → Backend
                                                    ↓
                                              LLM decides what
                                              tools to call
                                                    ↓
                                              Multi-step chains
                                              possible

Stateless requests                       Stateful context persists
Predictable request patterns             Dynamic, LLM-driven decisions
Human initiates each action              Agent chains multiple actions
Request = explicit intent                Request = natural language goal
```

---

## How MCPs Are Used in Enterprises

### Common Enterprise Use Cases

#### 1. Developer Productivity
```
Developer: "Find all TODOs in the codebase and create Jira tickets"
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  AI Agent (Cursor/Claude)                               │
│    │                                                    │
│    ├──► MCP: GitHub (search code for TODOs)            │
│    │        └──► Returns list of TODOs                 │
│    │                                                    │
│    ├──► MCP: Jira (create tickets)                     │
│    │        └──► Creates tickets, returns IDs          │
│    │                                                    │
│    └──► MCP: Slack (notify team)                       │
│             └──► Posts summary to #dev channel          │
└─────────────────────────────────────────────────────────┘
```

#### 2. Customer Support Automation
```
Support Agent: "Pull customer history and issue refund"
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  AI Agent                                               │
│    │                                                    │
│    ├──► MCP: Salesforce (get customer record)          │
│    │        └──► Returns order history                 │
│    │                                                    │
│    ├──► MCP: Stripe (process refund)                   │
│    │        └──► Executes payment refund               │
│    │                                                    │
│    └──► MCP: Zendesk (update ticket)                   │
│             └──► Closes ticket with resolution          │
└─────────────────────────────────────────────────────────┘
```

#### 3. Data Analysis & Reporting
```
Analyst: "Compare Q3 sales to Q2 and email summary to leadership"
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  AI Agent                                               │
│    │                                                    │
│    ├──► MCP: Postgres (query sales data)               │
│    │        └──► Returns quarterly figures             │
│    │                                                    │
│    ├──► MCP: Python/Code (calculate comparisons)       │
│    │        └──► Generates analysis                    │
│    │                                                    │
│    └──► MCP: Gmail (send email)                        │
│             └──► Sends report to leadership             │
└─────────────────────────────────────────────────────────┘
```

### Enterprise MCP Deployment Models

| Model | Description | Security Posture |
|-------|-------------|------------------|
| **Local/Desktop** | MCPs run on developer machines (Claude Desktop, Cursor) | No central visibility, shadow IT risk |
| **Project-level** | MCPs defined in repo configs (mcp.json) | Discoverable via code scanning |
| **Centralized** | Enterprise MCP gateway with approved servers | Controlled, but complex to implement |
| **Hybrid** | Mix of local + approved remote MCPs | Most common, hardest to secure |

---

## MCP Attack Surface & Threat Model

### The MCP Threat Landscape

```
┌─────────────────────────────────────────────────────────────────┐
│                    MCP ATTACK SURFACE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────────┐                                             │
│  │  SUPPLY CHAIN   │ ◄── Malicious packages, rug pulls          │
│  │    ATTACKS      │     typosquatting, compromised registries   │
│  └────────┬────────┘                                             │
│           │                                                       │
│           ▼                                                       │
│  ┌─────────────────┐                                             │
│  │   MCP SERVER    │ ◄── Tool poisoning, command injection      │
│  │  VULNERABILITIES│     unauthenticated access, RCE             │
│  └────────┬────────┘                                             │
│           │                                                       │
│           ▼                                                       │
│  ┌─────────────────┐                                             │
│  │   PROTOCOL      │ ◄── Token theft, session hijacking         │
│  │    ATTACKS      │     confused deputy, OAuth bypass           │
│  └────────┬────────┘                                             │
│           │                                                       │
│           ▼                                                       │
│  ┌─────────────────┐                                             │
│  │    LLM-LAYER    │ ◄── Prompt injection, tool shadowing       │
│  │    ATTACKS      │     context poisoning, jailbreaking         │
│  └─────────────────┘                                             │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Top 25 MCP Vulnerabilities (per Adversa AI Research)

#### Critical Severity

| # | Vulnerability | Description |
|---|--------------|-------------|
| 1 | **Prompt Injection** | Malicious prompts manipulate LLM behavior, exploiting inability to distinguish legitimate instructions from attacks |
| 2 | **Command Injection** | User input passes directly to OS commands without sanitization, enabling shell metacharacter attacks |
| 3 | **Tool Poisoning (TPA)** | Malicious instructions hidden in tool descriptions using Unicode tricks execute when LLM processes the tool |
| 4 | **Remote Code Execution** | Arbitrary code execution via command injection, unsafe deserialization, or memory corruption |
| 5 | **Unauthenticated Access** | MCP endpoints accessible without authentication, enabling unrestricted command execution |

#### High Severity

| # | Vulnerability | Description |
|---|--------------|-------------|
| 6 | **Confused Deputy (OAuth)** | Servers holding OAuth tokens fail to isolate actions, allowing privilege escalation |
| 7 | **Config Poisoning** | Malicious config files in repos silently compromise developer environments |
| 8 | **Token/Credential Theft** | API keys exposed in logs, memory, or insecure storage |
| 9 | **Token Passthrough** | Servers blindly forward user tokens without validation |
| 10 | **Path Traversal** | Directory traversal bypasses access controls for file access |
| 11 | **Full Schema Poisoning** | Entire tool schema definitions compromised |
| 12 | **Tool Name Spoofing** | Malicious tools masquerade as legitimate using homoglyphs |
| 13 | **Localhost Bypass** | Services bound to 0.0.0.0 expose local services to network |
| 14 | **Rug Pull Attack** | Legitimate tools turn malicious through updates |
| 15 | **Advanced Tool Poisoning** | ML-based poisoning manipulates LLM through adversarial examples |

#### Medium Severity

| # | Vulnerability | Description |
|---|--------------|-------------|
| 16 | **Session Management Flaws** | Protocol lacks session lifecycle definition |
| 17 | **Tool Shadowing** | Malicious servers register tools matching legitimate names |
| 18 | **Resource Content Poisoning** | Malicious instructions in resources (docs, files) |
| 19 | **Privilege Abuse** | Tools granted excessive permissions |
| 20 | **Cross-Repo Data Theft** | Org-wide tokens access repos beyond scope |
| 21 | **SQL Injection** | User input concatenated into queries |

#### Low Severity

| # | Vulnerability | Description |
|---|--------------|-------------|
| 22 | **Context Bleeding** | Info leaks between sessions in multi-tenant |
| 23 | **Config File Exposure** | Credentials exposed in public configs |
| 24 | **Preference Manipulation** | Long-term manipulation via biased responses |
| 25 | **Cross-Tenant Exposure** | Data leaks between tenants in cloud MCPs |

### Real-World Incidents

| Incident | Impact | Root Cause |
|----------|--------|------------|
| **CVE-2025-6514 (mcp-remote)** | 437,000+ developer environments compromised | Command injection in OAuth proxy |
| **CVE-2025-49596 (MCP Inspector)** | Browser-based RCE | Insufficient input validation |
| **Supabase Cursor Agent** | Customer tokens exfiltrated | Privileged agent processing untrusted input |

---

## MCP vs API Security: Key Differences

### Fundamental Paradigm Shift

| Aspect | Traditional API | MCP |
|--------|----------------|-----|
| **Request Origin** | Human user via UI | AI agent via natural language |
| **Request Pattern** | Predictable, schema-defined | Dynamic, LLM-decided |
| **State** | Stateless (each request independent) | Stateful (context persists across calls) |
| **Chaining** | Explicit, coded by developer | Implicit, decided by LLM at runtime |
| **Attack Surface** | Request parameters, headers | Prompts, tool descriptions, context |
| **Trust Model** | Authenticate user, authorize action | Authenticate user, but agent acts autonomously |

### Why Traditional API Security Fails for MCP

```
TRADITIONAL API SECURITY              WHY IT FAILS FOR MCP
─────────────────────────────────────────────────────────────────────

Input validation at endpoint    →    LLM interprets natural language
                                     Can't validate "intent"

Rate limiting per user          →    Agent makes many calls for one goal
                                     Legitimate usage looks like abuse

RBAC on endpoints              →    Agent chains tools dynamically
                                     Lateral movement through chains

WAF pattern matching           →    Prompt injection doesn't match
                                     traditional attack signatures

Session isolation              →    Context persists, accumulates
                                     One poisoned response affects all

Token per request              →    Token delegated to agent
                                     Agent scope != user intent
```

### Security Controls Comparison

| Control | API Implementation | MCP Implementation |
|---------|-------------------|-------------------|
| **Authentication** | API keys, OAuth, JWT per request | OAuth 2.1 to MCP server, but agent holds token |
| **Authorization** | RBAC/ABAC on endpoints | Must validate at tool level + context level |
| **Input Validation** | Schema validation, sanitization | Prompt sanitization, tool description scanning |
| **Audit Logging** | Request/response logs | Full context chain logging required |
| **Rate Limiting** | Requests per time window | Agent behavior patterns, not just volume |

---

## What Makes Sense to Test

### Testing Categories for MCP

#### Category 1: Static Analysis (No Runtime Required)

| Test | Description | Testable Without Running MCP? | Priority |
|------|-------------|------------------------------|----------|
| **Supply Chain Risk** | Package age, downloads, maintainer, CVEs | Yes | Critical |
| **Credential Exposure** | API keys, tokens in config | Yes | Critical |
| **Permission Scope** | What capabilities are granted | Yes (config analysis) | High |
| **Known Vulnerabilities** | CVE matching against registry | Yes | High |
| **Configuration Hygiene** | Secure defaults, unnecessary permissions | Yes | Medium |

#### Category 2: Server-Level Testing (Requires Running MCP)

| Test | Description | What to Look For | Priority |
|------|-------------|------------------|----------|
| **Tool Description Analysis** | Scan for hidden instructions | Unicode tricks, encoded commands | Critical |
| **Command Injection** | Test tool inputs for shell escapes | Shell metacharacters in parameters | Critical |
| **Path Traversal** | Test file access tools | `../` sequences, symlink following | High |
| **SQL Injection** | Test database tools | SQL syntax in natural language inputs | High |
| **Authentication Bypass** | Test auth mechanisms | Missing auth, default credentials | High |

#### Category 3: Behavioral/Runtime Testing (Requires Full Integration)

| Test | Description | What to Look For | Priority |
|------|-------------|------------------|----------|
| **Prompt Injection** | Malicious prompts in user input | Agent following injected instructions | Critical |
| **Tool Chaining Abuse** | Multi-step privilege escalation | Unexpected tool sequences | High |
| **Context Poisoning** | Malicious data in tool responses | Agent behavior change after processing | High |
| **Data Exfiltration** | Tools sending data externally | Unexpected network calls, data in URLs | High |
| **Rug Pull Detection** | Tool behavior changes over time | Hash changes, capability drift | Medium |

### MCP-Specific Risk Categories

| Category | Description | Testing Approach |
|----------|-------------|------------------|
| **Capability Risk** | What can this MCP do? | Enumerate tools, map to actions |
| **Supply Chain Risk** | Is the source trustworthy? | Registry lookup, package analysis |
| **Configuration Risk** | Are secrets exposed? Overprivileged? | Static config analysis |
| **Behavioral Risk** | Does it do what it claims? | Runtime monitoring, output analysis |
| **Integration Risk** | How does it interact with other MCPs? | Chain analysis, cross-MCP flows |

---

## What Does NOT Apply to MCP Testing

### Traditional API Tests That Don't Translate

| API Security Test | Why It Doesn't Apply to MCP |
|-------------------|----------------------------|
| **BOLA (Broken Object Level Auth)** | MCPs don't have object-level access patterns. The AI accesses capabilities, not user-specific objects. Access is granted at config time, not per-request. |
| **BFLA (Broken Function Level Auth)** | MCP tools are either available or not. There's no "admin vs user" function set - the capability is the authorization. |
| **Mass Assignment** | MCPs use structured tool calls, not form submissions. The schema is defined by the MCP server, not user input. |
| **SSRF (in traditional sense)** | The MCP itself is designed to access external resources. The risk is overly permissive access, not tricking the server into making requests. |
| **Rate Limiting (traditional)** | An AI agent legitimately makes many calls. Rate limiting must be context-aware, not just volume-based. |
| **CORS** | MCPs use different transport (stdio, SSE). Browser-based CORS doesn't apply to most MCP architectures. |
| **API Versioning Issues** | MCP has its own protocol version. The versioning concerns are different (tool schema changes, capability drift). |

### Why These Don't Work

```
TRADITIONAL API ASSUMPTION          MCP REALITY
─────────────────────────────────────────────────────────────────────

"User A shouldn't access           →  There's only one "user" (the agent)
 User B's data"                        acting on behalf of the human

"Admin functions need              →  All granted tools are "authorized"
 elevated permissions"                 The question is what should be granted

"Limit to 100 requests/minute"     →  Agent completing one task may need
                                       50 tool calls legitimately

"Block requests to internal IPs"   →  MCP is supposed to access internal
                                       resources - that's its job
```

### What's Different, Not Missing

These API security concepts have MCP equivalents, but they work differently:

| API Concept | MCP Equivalent |
|-------------|----------------|
| **BOLA** | **Capability Sprawl** - Does this MCP have access to resources it shouldn't? |
| **BFLA** | **Tool Enumeration** - What tools are exposed? Should they be? |
| **Rate Limiting** | **Behavioral Analysis** - Is the agent doing something unusual for this context? |
| **Input Validation** | **Prompt Sanitization** - Is the natural language input safe to process? |
| **SSRF** | **Scope Validation** - Is the MCP accessing resources within its intended scope? |

---

## Testing Methodology by Phase

### Phase 1: Discovery & Inventory (Static)

**Objective:** Understand what MCPs exist in the environment

| Action | Tool/Method | Output |
|--------|-------------|--------|
| Scan local configs | mcp-audit CLI | List of installed MCPs |
| Scan repositories | GitHub Action, code search | MCPs in project configs |
| Scan CI/CD | Pipeline analysis | MCPs used in automation |
| Map to registry | Known MCP database | Known vs unknown MCPs |

**Tests at this phase:**
- [ ] Enumerate all MCPs across org
- [ ] Identify unknown/unverified MCPs
- [ ] Check for secrets in configurations
- [ ] Assess supply chain risk (package age, downloads, CVEs)
- [ ] Document permission scope granted

### Phase 2: Configuration Analysis (Static)

**Objective:** Assess risk from configuration alone

| Check | Risk Indicator | Severity |
|-------|---------------|----------|
| Secrets in env | `API_KEY`, `TOKEN`, `PASSWORD` in config | Critical |
| Overprivileged | Shell + filesystem + network access | High |
| Unknown source | Not from verified publisher | High |
| Local binary | Running arbitrary executable | High |
| Remote without TLS | HTTP instead of HTTPS | High |
| Wide file access | Access to `/` or `$HOME` | Medium |

### Phase 3: Server Analysis (Requires Running MCP)

**Objective:** Analyze the MCP server's exposed capabilities

| Test | Method | What to Look For |
|------|--------|------------------|
| Tool enumeration | Connect and list tools | Unexpected capabilities |
| Description scanning | Parse tool descriptions | Hidden instructions, Unicode tricks |
| Schema analysis | Examine input schemas | Overly permissive inputs |
| Resource enumeration | List exposed resources | Sensitive data exposure |
| Auth testing | Test without credentials | Unauthenticated access |

### Phase 4: Vulnerability Testing (Requires Running MCP)

**Objective:** Test for exploitable vulnerabilities

| Vulnerability | Test Method | Payload Examples |
|---------------|-------------|------------------|
| Command injection | Inject shell metacharacters | `; id`, `| cat /etc/passwd` |
| Path traversal | Test file paths | `../../../etc/passwd` |
| SQL injection | Test database tools | `'; DROP TABLE--` |
| Prompt injection | Inject via tool inputs | `Ignore previous instructions...` |
| Tool poisoning | Analyze descriptions | Check for hidden Unicode |

### Phase 5: Behavioral Analysis (Full Integration)

**Objective:** Understand runtime behavior in context

| Analysis | Method | Risk Indicators |
|----------|--------|-----------------|
| Tool chain mapping | Monitor multi-step operations | Unexpected escalation paths |
| Data flow analysis | Track data through agent | Sensitive data to external tools |
| Context monitoring | Log full conversation context | Poisoned context persisting |
| Capability drift | Hash tool definitions over time | Rug pull detection |

---

## Recommendations

### For mcp-audit Product Strategy

#### Tier 1: Discovery (Free / Open Source)

**Value Proposition:** "Know what MCPs exist in your org"

| Capability | Implementation | Effort |
|------------|----------------|--------|
| Local scanning | Already built | Done |
| GitHub/repo scanning | Already built | Done |
| Registry matching | Already built | Done |
| Supply chain enrichment | Add npm/pip API calls | Low |
| CI/CD integration | GitHub Action | Medium |

#### Tier 2: Assessment (Paid - Team/Enterprise)

**Value Proposition:** "Understand the risk of your MCPs"

| Capability | Implementation | Effort |
|------------|----------------|--------|
| Org-wide dashboard | Web platform | Medium |
| Historical tracking | Database + UI | Medium |
| Policy enforcement | Config-as-code | Medium |
| Compliance reports | PDF generation | Low |
| Alerting | Webhook/email | Low |
| API access | REST API | Medium |

#### Tier 3: Deep Assessment (Paid - Enterprise+)

**Value Proposition:** "Validate your MCPs are secure"

| Capability | Implementation | Effort |
|------------|----------------|--------|
| Connect to running MCPs | MCP client SDK | High |
| Tool description scanning | NLP/pattern matching | Medium |
| Vulnerability testing | Test automation | High |
| Behavioral monitoring | Runtime proxy | High |
| Rug pull detection | Hash monitoring | Medium |

### Testing Priority Matrix

| Test Category | Requires Runtime? | Customer Value | Implementation Effort | Recommend for Tier |
|---------------|-------------------|----------------|----------------------|-------------------|
| Supply chain risk | No | High | Low | 1 (Free) |
| Secret detection | No | High | Low | 1 (Free) |
| Permission analysis | No | High | Low | 1 (Free) |
| Known CVE matching | No | High | Low | 1 (Free) |
| Org-wide visibility | No | High | Medium | 2 (Team) |
| Policy enforcement | No | High | Medium | 2 (Enterprise) |
| Tool description scanning | Yes | Critical | Medium | 3 (Enterprise+) |
| Command injection testing | Yes | Critical | High | 3 (Enterprise+) |
| Behavioral analysis | Yes | High | High | 3 (Enterprise+) |

### Key Takeaways

1. **MCP security is NOT API security** - The attack vectors, trust models, and testing methodologies are fundamentally different.

2. **Static analysis provides significant value** - You don't need running MCPs to identify supply chain risks, credential exposure, and permission issues.

3. **Discovery is the foundation** - Before you can secure MCPs, you need to know what exists. This is the gap mcp-audit fills.

4. **The market is early** - With MCP adoption exploding and security lagging, there's a clear opportunity for purpose-built MCP security tooling.

5. **Enterprise pain is real** - The challenges around governance, visibility, and compliance are well-documented and growing.

---

## References

- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [MCP Security: TOP 25 Vulnerabilities - Adversa AI](https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/)
- [MCP Security Issues - Docker](https://www.docker.com/blog/mcp-security-issues-threatening-ai-infrastructure/)
- [Enterprise Challenges with MCP - Christian Posta](https://blog.christianposta.com/enterprise-challenges-with-mcp-adoption/)
- [MCP vs Traditional API Security - Security Boulevard](https://securityboulevard.com/2025/12/mcp-vs-traditional-api-security-key-differences/)
- [MCP Tools: Attack Vectors - Elastic Security Labs](https://www.elastic.co/security-labs/mcp-tools-attack-defense-recommendations)
- [Tool Poisoning Attacks - Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/draft/basic/authorization)
- [5 Enterprise Challenges in Deploying Remote MCP - Descope](https://www.descope.com/blog/post/enterprise-mcp)
