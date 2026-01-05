# Security Advisory: MCP-AUDIT-2025-001

We acknowledge and thank the researcher for responsibly disclosing MCP-AUDIT-2025-001. We agree with the High severity rating. The lack of integrity validation on the local registry file represented a significant trust anchor vulnerability.

**Remediation (v0.1.2):** We have implemented the recommended SHA-256 hash verification. The tool now validates the registry file against a hardcoded hash on each load and displays a clear warning if tampering is detected.

**Long-term:** We are evaluating remote attestation with signed registry updates for a future release.

All users should update to v0.1.2 immediately.
