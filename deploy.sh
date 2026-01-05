#!/bin/bash

# MCP Audit - Deploy Script
# Deploys webapp changes to GitHub Pages
#
# Usage:
#   ./deploy.sh "Your commit message"
#
# Example:
#   ./deploy.sh "Fix table layout bug"

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REPO="apisec-inc/mcp-audit"
WEBAPP_DIR="$(dirname "$0")/webapp"
TEMP_DIR="/tmp/mcp-audit-deploy-$$"

# Check for commit message
if [ -z "$1" ]; then
    echo -e "${RED}Error: Please provide a commit message${NC}"
    echo ""
    echo "Usage: ./deploy.sh \"Your commit message\""
    echo "Example: ./deploy.sh \"Fix table layout bug\""
    exit 1
fi

COMMIT_MSG="$1"

# Check for GitHub token
if [ -z "$GITHUB_TOKEN" ]; then
    echo -e "${YELLOW}GitHub token not found in environment.${NC}"
    echo ""
    read -sp "Enter your GitHub Personal Access Token: " GITHUB_TOKEN
    echo ""

    if [ -z "$GITHUB_TOKEN" ]; then
        echo -e "${RED}Error: Token is required${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}=== MCP Audit Deployment ===${NC}"
echo ""

# Step 1: Clone the repo
echo -e "${YELLOW}[1/4] Cloning repository...${NC}"
git clone --quiet "https://${GITHUB_TOKEN}@github.com/${REPO}.git" "$TEMP_DIR"

# Step 2: Copy webapp files
echo -e "${YELLOW}[2/4] Copying updated files...${NC}"
cp "$WEBAPP_DIR/index.html" "$TEMP_DIR/"
cp "$WEBAPP_DIR/app.js" "$TEMP_DIR/"
cp "$WEBAPP_DIR/styles.css" "$TEMP_DIR/"
if [ -f "$WEBAPP_DIR/getting-started.html" ]; then
    cp "$WEBAPP_DIR/getting-started.html" "$TEMP_DIR/"
fi
if [ -f "$WEBAPP_DIR/mcp-audit-cli.zip" ]; then
    cp "$WEBAPP_DIR/mcp-audit-cli.zip" "$TEMP_DIR/"
fi

# Step 3: Commit and push
echo -e "${YELLOW}[3/4] Committing changes...${NC}"
cd "$TEMP_DIR"
git add .

# Check if there are changes to commit
if git diff --staged --quiet; then
    echo -e "${YELLOW}No changes detected. Nothing to deploy.${NC}"
    rm -rf "$TEMP_DIR"
    exit 0
fi

git commit -m "$COMMIT_MSG"

echo -e "${YELLOW}[4/4] Pushing to GitHub...${NC}"
git push

# Cleanup
cd - > /dev/null
rm -rf "$TEMP_DIR"

echo ""
echo -e "${GREEN}=== Deployment Complete ===${NC}"
echo ""
echo "Your changes will be live in 1-2 minutes at:"
echo -e "${GREEN}https://apisec-inc.github.io/mcp-audit/${NC}"
echo ""
echo "View the repo at:"
echo "https://github.com/${REPO}"
