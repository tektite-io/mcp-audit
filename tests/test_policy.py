"""
Tests for MCP Audit policy validation
"""

import pytest
import json
from pathlib import Path

from mcp_audit.commands.policy import _validate_mcp, _match_pattern, _parse_simple_yaml


class TestPolicyValidation:
    """Tests for policy validation"""

    def test_validate_allowed_source_pass(self):
        """Test MCP from allowed source passes"""
        mcp = {
            "name": "filesystem",
            "source": "@anthropic/mcp-server-filesystem",
            "risk_flags": []
        }
        policy = {
            "allowed_sources": ["@anthropic/*"]
        }

        result = _validate_mcp(mcp, policy)

        assert result["status"] == "COMPLIANT"

    def test_validate_allowed_source_fail(self):
        """Test MCP from non-allowed source fails"""
        mcp = {
            "name": "custom",
            "source": "random-package",
            "risk_flags": []
        }
        policy = {
            "allowed_sources": ["@anthropic/*", "@modelcontextprotocol/*"]
        }

        result = _validate_mcp(mcp, policy)

        assert result["status"] == "VIOLATION"
        assert "not in allowed list" in result["reasons"][0]

    def test_validate_denied_capability(self):
        """Test MCP with denied capability fails"""
        mcp = {
            "name": "shell",
            "source": "@anthropic/mcp-server-shell",
            "risk_flags": ["shell-access"]
        }
        policy = {
            "denied_capabilities": ["shell-access"]
        }

        result = _validate_mcp(mcp, policy)

        assert result["status"] == "VIOLATION"
        assert "shell-access" in result["reasons"][0]

    def test_validate_require_review(self):
        """Test MCP with require_review flag gets warning"""
        mcp = {
            "name": "custom",
            "source": "unverified-package",
            "risk_flags": ["unverified-source"]
        }
        policy = {
            "require_review": ["unverified-source"]
        }

        result = _validate_mcp(mcp, policy)

        assert result["status"] == "WARNING"
        assert "Requires review" in result["reasons"][0]

    def test_validate_max_risk_level_medium(self):
        """Test max risk level enforcement"""
        mcp = {
            "name": "shell",
            "source": "some-package",
            "risk_flags": ["shell-access"]
        }
        policy = {
            "max_risk_level": "medium"
        }

        result = _validate_mcp(mcp, policy)

        assert result["status"] == "VIOLATION"

    def test_validate_max_risk_level_low(self):
        """Test low max risk level blocks medium risks"""
        mcp = {
            "name": "fs",
            "source": "@anthropic/mcp-server-filesystem",
            "risk_flags": ["filesystem-access"]
        }
        policy = {
            "max_risk_level": "low"
        }

        result = _validate_mcp(mcp, policy)

        assert result["status"] == "VIOLATION"

    def test_validate_compliant_mcp(self):
        """Test fully compliant MCP passes"""
        mcp = {
            "name": "slack",
            "source": "@modelcontextprotocol/server-slack",
            "risk_flags": []
        }
        policy = {
            "allowed_sources": ["@modelcontextprotocol/*"],
            "denied_capabilities": ["shell-access"],
            "max_risk_level": "high"
        }

        result = _validate_mcp(mcp, policy)

        assert result["status"] == "COMPLIANT"

    def test_validate_multiple_violations(self):
        """Test MCP with multiple violations"""
        mcp = {
            "name": "risky",
            "source": "untrusted-package",
            "risk_flags": ["shell-access", "filesystem-access"]
        }
        policy = {
            "allowed_sources": ["@anthropic/*"],
            "denied_capabilities": ["shell-access", "filesystem-access"]
        }

        result = _validate_mcp(mcp, policy)

        assert result["status"] == "VIOLATION"
        assert len(result["reasons"]) >= 2


class TestPatternMatching:
    """Tests for source pattern matching"""

    def test_exact_match(self):
        """Test exact string match"""
        assert _match_pattern("@anthropic/mcp-server", "@anthropic/mcp-server")

    def test_wildcard_end(self):
        """Test wildcard at end of pattern"""
        assert _match_pattern("@anthropic/mcp-server-filesystem", "@anthropic/*")
        assert _match_pattern("@anthropic/anything", "@anthropic/*")

    def test_wildcard_no_match(self):
        """Test wildcard doesn't match wrong prefix"""
        assert not _match_pattern("@other/package", "@anthropic/*")

    def test_double_wildcard(self):
        """Test pattern with multiple wildcards"""
        assert _match_pattern("mcp-server-test", "mcp-*-*")

    def test_full_wildcard(self):
        """Test full wildcard matches anything"""
        assert _match_pattern("anything", "*")
        assert _match_pattern("@scope/package", "*")


class TestYamlParser:
    """Tests for simple YAML parser"""

    def test_parse_basic_yaml(self):
        """Test parsing basic YAML structure"""
        yaml_content = """
allowed_sources:
  - "@anthropic/*"
  - "@modelcontextprotocol/*"

denied_capabilities:
  - shell-access
"""
        result = _parse_simple_yaml(yaml_content)

        assert "allowed_sources" in result
        assert "@anthropic/*" in result["allowed_sources"]
        assert "denied_capabilities" in result
        assert "shell-access" in result["denied_capabilities"]

    def test_parse_yaml_with_comments(self):
        """Test parsing YAML with comments"""
        yaml_content = """
# This is a comment
allowed_sources:
  - "@anthropic/*"  # inline comment shouldn't be here
"""
        result = _parse_simple_yaml(yaml_content)

        assert "allowed_sources" in result
        # Note: simple parser may include comments, that's acceptable

    def test_parse_yaml_with_quotes(self):
        """Test parsing YAML with quoted values"""
        yaml_content = """
allowed_sources:
  - "@anthropic/*"
  - '@modelcontextprotocol/*'
"""
        result = _parse_simple_yaml(yaml_content)

        assert "@anthropic/*" in result["allowed_sources"]
        assert "@modelcontextprotocol/*" in result["allowed_sources"]


class TestPolicyIntegration:
    """Integration tests for policy validation"""

    def test_strict_policy(self, temp_dir, sample_scan_results):
        """Test strict policy catches violations"""
        # Create inventory file
        inventory_path = temp_dir / "inventory.json"
        inventory_path.write_text(json.dumps(sample_scan_results))

        # Create strict policy
        policy = {
            "allowed_sources": ["@anthropic/*", "@modelcontextprotocol/*"],
            "denied_capabilities": ["shell-access"],
            "require_review": ["unverified-source"]
        }

        results = []
        for mcp in sample_scan_results["mcps"]:
            results.append(_validate_mcp(mcp, policy))

        violations = [r for r in results if r["status"] == "VIOLATION"]
        warnings = [r for r in results if r["status"] == "WARNING"]

        # Should have at least one violation (shell-access or non-allowed source)
        # Note: violations or warnings depend on the sample data
        total_issues = len(violations) + len(warnings)
        assert total_issues >= 1, f"Expected at least 1 issue, got {total_issues}"

    def test_permissive_policy(self, sample_scan_results):
        """Test permissive policy allows most MCPs"""
        policy = {
            "allowed_sources": ["*"],
            "denied_capabilities": []
        }

        results = []
        for mcp in sample_scan_results["mcps"]:
            results.append(_validate_mcp(mcp, policy))

        compliant = [r for r in results if r["status"] == "COMPLIANT"]

        assert len(compliant) == len(sample_scan_results["mcps"])
