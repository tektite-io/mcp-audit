#!/bin/bash

# MCP Audit - Deploy Script
# Deploys webapp changes to GitHub Pages (Production)
#
# Usage:
#   ./deploy.sh "Your commit message"
#   ./deploy.sh --preview     # Show what would be deployed without deploying
#
# Workflow:
#   1. Test locally: ./scripts/dev-server.sh
#   2. Review changes: ./deploy.sh --preview
#   3. Deploy to prod: ./deploy.sh "Your commit message"

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="apisec-inc/mcp-audit"
SCRIPT_DIR="$(dirname "$0")"
TEMP_DIR="/tmp/mcp-audit-deploy-$$"

# Files to deploy (from root, since webapp files are now at root)
DEPLOY_FILES=(
    "index.html"
    "app.js"
    "styles.css"
    "getting-started.html"
    "mcp-audit-cli.zip"
)

# Preview mode
if [ "$1" == "--preview" ]; then
    echo -e "${BLUE}=== Deployment Preview ===${NC}"
    echo ""
    echo "Files that would be deployed to production:"
    echo ""
    for file in "${DEPLOY_FILES[@]}"; do
        if [ -f "$SCRIPT_DIR/$file" ]; then
            size=$(ls -lh "$SCRIPT_DIR/$file" | awk '{print $5}')
            modified=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$SCRIPT_DIR/$file" 2>/dev/null || stat -c "%y" "$SCRIPT_DIR/$file" 2>/dev/null | cut -d'.' -f1)
            echo -e "  ${GREEN}✓${NC} $file ($size, modified: $modified)"
        else
            echo -e "  ${YELLOW}○${NC} $file (not found, will skip)"
        fi
    done
    echo ""
    echo "Target: https://apisec-inc.github.io/mcp-audit/"
    echo ""
    echo -e "${YELLOW}To deploy, run:${NC}"
    echo "  ./deploy.sh \"Your commit message\""
    exit 0
fi

# Check for commit message
if [ -z "$1" ]; then
    echo -e "${RED}Error: Please provide a commit message${NC}"
    echo ""
    echo "Usage:"
    echo "  ./deploy.sh \"Your commit message\"   # Deploy to production"
    echo "  ./deploy.sh --preview                # Preview what would be deployed"
    echo ""
    echo "Recommended workflow:"
    echo "  1. Test locally:    ./scripts/dev-server.sh"
    echo "  2. Preview changes: ./deploy.sh --preview"
    echo "  3. Deploy to prod:  ./deploy.sh \"Your commit message\""
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

echo -e "${GREEN}=== MCP Audit - Production Deployment ===${NC}"
echo ""

# Show what will be deployed
echo -e "${BLUE}Files to deploy:${NC}"
for file in "${DEPLOY_FILES[@]}"; do
    if [ -f "$SCRIPT_DIR/$file" ]; then
        echo -e "  ${GREEN}✓${NC} $file"
    fi
done
echo ""

# Confirmation
echo -e "${YELLOW}This will deploy to PRODUCTION:${NC}"
echo "  https://apisec-inc.github.io/mcp-audit/"
echo ""
read -p "Continue? (y/N): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Deployment cancelled.${NC}"
    exit 0
fi
echo ""

# Step 1: Clone the repo
echo -e "${YELLOW}[1/4] Cloning repository...${NC}"
git clone --quiet "https://${GITHUB_TOKEN}@github.com/${REPO}.git" "$TEMP_DIR"

# Step 2: Copy webapp files
echo -e "${YELLOW}[2/4] Copying updated files...${NC}"
for file in "${DEPLOY_FILES[@]}"; do
    if [ -f "$SCRIPT_DIR/$file" ]; then
        cp "$SCRIPT_DIR/$file" "$TEMP_DIR/"
        echo "  Copied: $file"
    fi
done

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
echo "View deployment at:"
echo "https://github.com/${REPO}/actions"
