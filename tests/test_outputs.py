"""
Tests for MCP Audit output formatters
"""

import pytest
import json
from mcp_audit.outputs import formatter
from mcp_audit.models import ScanResult, CollectedConfig


class TestResultsFormatter:
    """Tests for scan results formatter"""

    @pytest.fixture
    def sample_results(self):
        """Create sample scan results"""
        return [
            ScanResult(
                name="filesystem",
                source="@anthropic/mcp-server-filesystem",
                found_in="Claude Desktop",
                server_type="npm",
                config_path="/home/user/.config/claude.json",
                risk_flags=["filesystem-access"]
            ),
            ScanResult(
                name="slack",
                source="@modelcontextprotocol/server-slack",
                found_in="Claude Desktop",
                server_type="npm",
                config_path="/home/user/.config/claude.json",
                risk_flags=[]
            )
        ]

    def test_format_json(self, sample_results):
        """Test JSON output format"""
        output = formatter.format_results(sample_results, "json")
        data = json.loads(output)

        assert "scan_time" in data
        assert data["total_mcps"] == 2
        assert len(data["mcps"]) == 2
        assert data["mcps"][0]["name"] == "filesystem"

    def test_format_markdown(self, sample_results):
        """Test Markdown output format"""
        output = formatter.format_results(sample_results, "markdown")

        assert "# MCP Audit Report" in output
        assert "| filesystem |" in output
        assert "| slack |" in output
        assert "filesystem-access" in output

    def test_format_csv(self, sample_results):
        """Test CSV output format"""
        output = formatter.format_results(sample_results, "csv")
        lines = output.strip().split("\n")

        assert lines[0] == "name,source,found_in,server_type,risk_flags,secrets_count,secrets_severity,apis_count,api_categories,config_path"
        assert len(lines) == 3  # header + 2 results
        assert "filesystem" in lines[1]

    def test_format_table_returns_json(self, sample_results):
        """Test that table format falls back to JSON for string output"""
        output = formatter.format_results(sample_results, "table")
        # Table format returns JSON when not printing directly
        data = json.loads(output)
        assert data["total_mcps"] == 2


class TestAggregatedFormatter:
    """Tests for aggregated results formatter"""

    @pytest.fixture
    def sample_aggregated(self):
        """Create sample aggregated data"""
        mcps = {
            "filesystem": {
                "name": "filesystem",
                "source": "@anthropic/mcp-server-filesystem",
                "server_type": "npm",
                "machines": ["machine-1", "machine-2"],
                "risk_flags": {"filesystem-access"}
            },
            "slack": {
                "name": "slack",
                "source": "@modelcontextprotocol/server-slack",
                "server_type": "npm",
                "machines": ["machine-1"],
                "risk_flags": set()
            }
        }

        configs = [
            CollectedConfig(
                machine_id="machine-1",
                collected_at="2024-01-15T10:00:00Z",
                source_file="machine1.json",
                mcps=[
                    ScanResult(
                        name="filesystem",
                        source="@anthropic/mcp-server-filesystem",
                        found_in="Claude Desktop",
                        server_type="npm",
                        config_path="/path",
                        risk_flags=["filesystem-access"]
                    )
                ]
            ),
            CollectedConfig(
                machine_id="machine-2",
                collected_at="2024-01-15T11:00:00Z",
                source_file="machine2.json",
                mcps=[]
            )
        ]

        return mcps, configs

    def test_aggregated_json(self, sample_aggregated):
        """Test aggregated JSON output"""
        mcps, configs = sample_aggregated
        output = formatter.format_aggregated(mcps, configs, "json")
        data = json.loads(output)

        assert data["machines_reporting"] == 2
        assert data["unique_mcps"] == 2
        assert len(data["mcps"]) == 2

    def test_aggregated_markdown(self, sample_aggregated):
        """Test aggregated Markdown output"""
        mcps, configs = sample_aggregated
        output = formatter.format_aggregated(mcps, configs, "markdown")

        assert "# MCP Audit Report - Aggregated" in output
        assert "Machines Reporting" in output
        assert "filesystem" in output

    def test_aggregated_csv(self, sample_aggregated):
        """Test aggregated CSV output"""
        mcps, configs = sample_aggregated
        output = formatter.format_aggregated(mcps, configs, "csv")
        lines = output.strip().split("\n")

        assert "name,source,server_type,machine_count,risk_flags" in lines[0]
        assert len(lines) == 3  # header + 2 MCPs


class TestSpecialCases:
    """Tests for edge cases and special scenarios"""

    def test_empty_results(self):
        """Test formatting empty results"""
        output = formatter.format_results([], "json")
        data = json.loads(output)

        assert data["total_mcps"] == 0
        assert data["mcps"] == []

    def test_results_with_special_characters(self):
        """Test handling special characters in output"""
        results = [
            ScanResult(
                name="test,name",
                source="source,with,commas",
                found_in="Test App",
                server_type="npm",
                config_path="/path/with spaces/config.json",
                risk_flags=[]
            )
        ]

        # CSV should handle commas
        csv_output = formatter.format_results(results, "csv")
        assert '"source,with,commas"' in csv_output

        # JSON should escape properly
        json_output = formatter.format_results(results, "json")
        data = json.loads(json_output)
        assert data["mcps"][0]["source"] == "source,with,commas"

    def test_results_with_many_risk_flags(self):
        """Test handling multiple risk flags"""
        results = [
            ScanResult(
                name="risky-server",
                source="some-package",
                found_in="Test App",
                server_type="npm",
                config_path="/path",
                risk_flags=["shell-access", "filesystem-access", "database-access", "unverified-source"]
            )
        ]

        json_output = formatter.format_results(results, "json")
        data = json.loads(json_output)

        assert len(data["mcps"][0]["risk_flags"]) == 4
