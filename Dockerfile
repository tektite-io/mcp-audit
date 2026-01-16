# MCP Audit - Docker Image
# Lightweight container for running MCP security audits

FROM python:3.11-slim

LABEL org.opencontainers.image.title="MCP Audit"
LABEL org.opencontainers.image.description="Security audit tool for MCP configurations"
LABEL org.opencontainers.image.source="https://github.com/apisec-inc/mcp-audit"
LABEL org.opencontainers.image.vendor="APIsec"
LABEL org.opencontainers.image.licenses="MIT"

# Set working directory
WORKDIR /app

# Copy package files
COPY pyproject.toml README.md ./
COPY mcp_audit/ ./mcp_audit/

# Install the package
RUN pip install --no-cache-dir .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash mcpuser
USER mcpuser

# Set default working directory for scans
WORKDIR /scan

# Default command
ENTRYPOINT ["mcp-audit"]
CMD ["scan"]
