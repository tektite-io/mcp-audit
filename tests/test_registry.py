"""
Tests for MCP Registry functionality
"""

import pytest
from mcp_audit.data import (
    get_registry,
    lookup_mcp,
    get_mcps_by_provider,
    get_mcps_by_risk,
    get_verified_mcps,
    get_all_endpoints,
    get_risk_definition,
    get_type_definition,
)


class TestRegistryData:
    """Tests for registry data loading"""

    def test_get_registry_returns_dict(self):
        """Test that get_registry returns a dictionary"""
        registry = get_registry()
        assert isinstance(registry, dict)
        assert "mcps" in registry
        assert "version" in registry

    def test_registry_has_mcps(self):
        """Test that registry contains MCPs"""
        registry = get_registry()
        assert len(registry["mcps"]) > 0

    def test_registry_mcps_have_required_fields(self):
        """Test that all MCPs have required fields"""
        registry = get_registry()
        required_fields = ["name", "provider", "package", "type", "risk_level"]

        for mcp in registry["mcps"]:
            for field in required_fields:
                assert field in mcp, f"MCP {mcp.get('name', 'unknown')} missing {field}"


class TestMcpLookup:
    """Tests for MCP lookup functionality"""

    def test_lookup_anthropic_mcp(self):
        """Test looking up an official Anthropic MCP"""
        match = lookup_mcp("@anthropic/mcp-server-filesystem")

        assert match is not None
        assert match["provider"] == "Anthropic"
        assert match["type"] == "official"

    def test_lookup_mcp_partial_match(self):
        """Test that partial package name matches"""
        match = lookup_mcp("npx @anthropic/mcp-server-filesystem /home/user")

        assert match is not None
        assert "anthropic" in match["package"].lower()

    def test_lookup_unknown_mcp(self):
        """Test looking up an unknown MCP returns None"""
        match = lookup_mcp("completely-random-nonexistent-mcp-12345")

        assert match is None

    def test_lookup_case_insensitive(self):
        """Test that lookup is case-insensitive"""
        match1 = lookup_mcp("@ANTHROPIC/MCP-SERVER-FILESYSTEM")
        match2 = lookup_mcp("@anthropic/mcp-server-filesystem")

        assert match1 is not None
        assert match2 is not None
        assert match1["name"] == match2["name"]


class TestRegistryFiltering:
    """Tests for registry filtering functions"""

    def test_get_mcps_by_provider(self):
        """Test filtering MCPs by provider"""
        anthropic_mcps = get_mcps_by_provider("Anthropic")

        assert len(anthropic_mcps) > 0
        for mcp in anthropic_mcps:
            assert mcp["provider"].lower() == "anthropic"

    def test_get_mcps_by_risk_critical(self):
        """Test filtering MCPs by critical risk level"""
        critical_mcps = get_mcps_by_risk("critical")

        assert len(critical_mcps) > 0
        for mcp in critical_mcps:
            assert mcp["risk_level"] == "critical"

    def test_get_mcps_by_risk_low(self):
        """Test filtering MCPs by low risk level"""
        low_mcps = get_mcps_by_risk("low")

        assert len(low_mcps) > 0
        for mcp in low_mcps:
            assert mcp["risk_level"] == "low"

    def test_get_verified_mcps(self):
        """Test getting only verified MCPs"""
        verified = get_verified_mcps()

        assert len(verified) > 0
        for mcp in verified:
            assert mcp.get("verified", False) is True


class TestRegistryDefinitions:
    """Tests for risk and type definitions"""

    def test_get_risk_definition_critical(self):
        """Test getting critical risk definition"""
        definition = get_risk_definition("critical")

        assert definition is not None
        assert len(definition) > 0
        assert "unknown" not in definition.lower()

    def test_get_risk_definition_unknown(self):
        """Test getting unknown risk definition"""
        definition = get_risk_definition("nonexistent")

        assert "unknown" in definition.lower()

    def test_get_type_definition_official(self):
        """Test getting official type definition"""
        definition = get_type_definition("official")

        assert definition is not None
        assert len(definition) > 0

    def test_get_type_definition_unknown(self):
        """Test getting unknown type definition"""
        definition = get_type_definition("nonexistent")

        assert "unknown" in definition.lower()


class TestRegistryEndpoints:
    """Tests for endpoint-related functionality"""

    def test_get_all_endpoints(self):
        """Test getting MCPs with known endpoints"""
        endpoints = get_all_endpoints()

        # Some MCPs may have endpoints
        for mcp in endpoints:
            assert "endpoint" in mcp
            assert mcp["endpoint"] is not None
