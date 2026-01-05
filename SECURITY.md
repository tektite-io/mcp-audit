# Security Review - MCP Audit

## Overview

This document provides a security assessment of the MCP Audit tool, including dependency analysis, privacy considerations, and threat modeling.

---

## 1. Dependency Analysis

### CLI Tool Dependencies

| Package | Version | Purpose | Security Assessment |
|---------|---------|---------|---------------------|
| **typer** | >=0.9.0,<1.0.0 | CLI framework | ✅ **Low Risk** - Well-maintained by Sebastián Ramírez (FastAPI author). No known vulnerabilities. Minimal attack surface as it only processes command-line arguments. |
| **rich** | >=13.0.0,<14.0.0 | Terminal formatting | ✅ **Low Risk** - Popular library (47k+ GitHub stars). Output-only library with no network access, file system writes, or code execution. |

**Total direct dependencies: 2**

### Why These Dependencies Are Safe

1. **Minimal dependency tree** - Both packages have few transitive dependencies
2. **No network access** - Neither package makes network requests
3. **No file writes** - Neither package writes to the filesystem (Rich only outputs to terminal)
4. **No code execution** - Neither package executes arbitrary code
5. **Well-maintained** - Both have active maintainers and security practices

### Packages We Explicitly Avoided

| Package | Why Avoided |
|---------|-------------|
| requests | Would add network capability; not needed for local scanning |
| pyyaml | Has had CVEs; basic YAML support not critical |
| cryptography | Complex native code; not needed |
| Any database drivers | Would expand attack surface unnecessarily |

### Web App Dependencies

The web app has **zero external dependencies**. It uses:
- Vanilla JavaScript
- Fetch API (built into browsers)
- No npm packages
- No build step required

This is intentional - security tools should minimize their own attack surface.

---

## 2. Privacy Considerations

### CLI Tool

| Data | Collected? | Transmitted? | Storage |
|------|------------|--------------|---------|
| MCP configurations | Yes (read-only) | No | Memory only during scan |
| File paths | Yes | No | Included in output if user exports |
| Environment variables | Scanned for keys | No | Keys only, values not stored |
| Personal information | No | No | N/A |

**The CLI tool:**
- Reads configuration files (read-only)
- Never writes to scanned directories
- Never transmits data anywhere
- Only outputs to terminal or user-specified file

### Web App

| Data | Collected? | Transmitted? | Storage |
|------|------------|--------------|---------|
| GitHub token | Yes (user input) | To GitHub API only | Browser memory only |
| Repository contents | Yes | From GitHub only | Browser memory only |
| Scan results | Yes | Never | Browser memory only |

**The web app:**
- GitHub token never touches APIsec servers
- All API calls go directly from browser to GitHub
- No analytics or tracking (can be verified by inspecting source)
- No cookies or local storage used

### MDM Collector

| Data | Collected? | Transmitted? | Storage |
|------|------------|--------------|---------|
| MCP configurations | Yes | To specified output path | User-controlled location |
| Machine hostname | Yes | In output file | User-controlled location |
| User paths | Yes | In output file | User-controlled location |

**The collector:**
- Only collects MCP-specific configuration files
- Does not collect: browser history, credentials, personal files
- Output location is controlled by the deploying organization
- No data transmitted to APIsec

---

## 3. Threat Model

### Assets Protected

1. **MCP configurations** - Contains information about AI tool integrations
2. **Environment variables** - May contain API keys, secrets
3. **GitHub access** - Token provides repository access

### Threats Addressed

| Threat | Mitigation |
|--------|------------|
| Data exfiltration via tool | No network capability in CLI; web app only contacts GitHub |
| Credential theft | Tokens stored in memory only, never persisted |
| Malicious dependencies | Minimal, well-audited dependencies |
| Supply chain attack | Pinned versions, dependency review process |

### Threats NOT Addressed (Out of Scope)

| Threat | Why Out of Scope |
|--------|------------------|
| Malicious MCPs discovered | Tool reports findings; remediation is user's responsibility |
| Compromised developer machine | Collector runs with existing permissions |
| GitHub token misuse | User responsible for token scope and rotation |

### Attack Vectors Considered

#### 1. Dependency Compromise

**Risk:** A dependency could be compromised to exfiltrate data.

**Mitigations:**
- Only 2 direct dependencies
- Both are well-established, high-profile packages
- Version pinning prevents unexpected updates
- Dependencies have no network access

**Residual Risk:** Low

#### 2. Web App Code Injection

**Risk:** Malicious repository content could inject code via XSS.

**Mitigations:**
- All user content is escaped before display (`escapeHtml()` function)
- No use of `innerHTML` with untrusted content
- No `eval()` or dynamic code execution
- Content Security Policy recommended for deployment

**Residual Risk:** Low

#### 3. GitHub Token Exposure

**Risk:** Token could be exposed through logs, errors, or transmission.

**Mitigations:**
- Token stored only in JavaScript variable (memory)
- Token passed only in Authorization header to GitHub
- No logging of token value
- Token not included in any output/export

**Residual Risk:** Low

#### 4. Collector Script Tampering

**Risk:** MDM script could be modified to collect additional data.

**Mitigations:**
- Script is open source and auditable
- Organizations should review before deployment
- Script only reads specific, documented paths
- No network transmission in script itself

**Residual Risk:** Medium (depends on org's MDM security)

---

## 4. Secure Deployment Checklist

### CLI Tool

- [ ] Install from trusted source (GitHub releases or PyPI)
- [ ] Verify package integrity (checksums if available)
- [ ] Review output before sharing (may contain paths, hostnames)
- [ ] Run with minimal permissions (no sudo needed)

### Web App

- [ ] Host on HTTPS only
- [ ] Add Content Security Policy headers
- [ ] Disable directory listing
- [ ] Review source code before deployment
- [ ] Consider self-hosting for sensitive environments

### MDM Collector

- [ ] Review script before deployment
- [ ] Restrict output location access
- [ ] Use secure transport for collected files
- [ ] Implement file integrity monitoring on output location
- [ ] Rotate collection location periodically

---

## 5. Incident Response

### If a vulnerability is found in this tool:

1. Report to security@apisec.ai (or create GitHub security advisory)
2. Do not disclose publicly until patch is available
3. We will respond within 48 hours
4. Patches will be released as new versions

### If you suspect your scan data was compromised:

1. Rotate any credentials found in MCP configs
2. Review GitHub token permissions and revoke if necessary
3. Check MCP configurations for unexpected changes
4. Report incident to your security team

---

## 6. Version History

| Version | Date | Security Changes |
|---------|------|------------------|
| 0.1.0 | Initial | Initial security review completed |

---

## 7. Auditor Notes

This security review was performed by the development team. For production use in high-security environments, we recommend:

1. Independent security audit
2. Penetration testing of web app
3. Code review by your security team
4. Deployment in isolated environment first

---

*Last updated: [Date]*
*Reviewed by: APIsec Security Team*
