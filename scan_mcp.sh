#!/usr/bin/env bash
set -euo pipefail

MCP_SCANNER_DIR="$HOME/dev/mcp-scanner"
SCAN_TMP_DIR="/tmp/mcp-scan-target"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}         MCP Security Scanner           ${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Step 1: Clone mcp-scanner if not already present
if [ ! -d "$MCP_SCANNER_DIR" ]; then
    echo -e "${YELLOW}Cloning mcp-scanner into $MCP_SCANNER_DIR...${NC}"
    git clone https://github.com/cisco-ai-defense/mcp-scanner "$MCP_SCANNER_DIR"
else
    echo -e "${GREEN}mcp-scanner already present at $MCP_SCANNER_DIR${NC}"
fi

# Step 2: Ensure mcp-scanner CLI is installed
if ! command -v mcp-scanner &>/dev/null; then
    echo -e "${YELLOW}Installing mcp-scanner CLI...${NC}"
    uv tool install --python 3.13 cisco-ai-mcp-scanner
fi

# Step 3: Set LLM model
export MCP_SCANNER_LLM_MODEL="anthropic/claude-sonnet-4-6"

# Step 4: Ask for Anthropic API key
echo ""
echo -e "${CYAN}Enter your Anthropic API key (sk-ant-...):${NC}"
read -rs MCP_SCANNER_LLM_API_KEY
if [ -z "$MCP_SCANNER_LLM_API_KEY" ]; then
    echo -e "${RED}Error: API key cannot be empty.${NC}"
    exit 1
fi
export MCP_SCANNER_LLM_API_KEY
echo -e "${GREEN}API key set.${NC}"

# Step 5: Ask what to scan
echo ""
echo -e "${CYAN}What MCP repo would you like to scan?${NC}"
echo -e "  - GitHub URL (e.g. https://github.com/owner/repo)"
echo -e "  - Local path  (e.g. /path/to/mcp-server/src)"
echo ""
read -rp "Enter repo URL or local path: " SCAN_TARGET

if [ -z "$SCAN_TARGET" ]; then
    echo -e "${RED}Error: No target provided.${NC}"
    exit 1
fi

# Step 6: Resolve target to a local source path
if [[ "$SCAN_TARGET" == http* ]]; then
    echo ""
    echo -e "${YELLOW}Cloning $SCAN_TARGET into $SCAN_TMP_DIR ...${NC}"
    rm -rf "$SCAN_TMP_DIR"
    git clone "$SCAN_TARGET" "$SCAN_TMP_DIR"
    SOURCE_PATH="$SCAN_TMP_DIR"
    # Use src/ subdirectory if it exists
    if [ -d "$SCAN_TMP_DIR/src" ]; then
        SOURCE_PATH="$SCAN_TMP_DIR/src"
    fi
else
    SOURCE_PATH="$SCAN_TARGET"
fi

if [ ! -d "$SOURCE_PATH" ]; then
    echo -e "${RED}Error: Path $SOURCE_PATH does not exist.${NC}"
    exit 1
fi

echo ""
# Step 7: Build analyzer list based on available keys
ANALYZERS="yara,behavioral,readiness"

if [ -n "${VIRUSTOTAL_API_KEY:-}" ]; then
    ANALYZERS="$ANALYZERS,virustotal"
fi

if [ -n "${MCP_SCANNER_API_KEY:-}" ]; then
    ANALYZERS="$ANALYZERS,api"
fi

echo -e "${CYAN}Scanning: $SOURCE_PATH${NC}"
echo -e "${CYAN}Analyzers: $ANALYZERS${NC}"
[ -z "${VIRUSTOTAL_API_KEY:-}" ] && echo -e "${YELLOW}  + virustotal skipped (set VIRUSTOTAL_API_KEY to enable)${NC}"
[ -z "${MCP_SCANNER_API_KEY:-}" ] && echo -e "${YELLOW}  + cisco api skipped (set MCP_SCANNER_API_KEY to enable)${NC}"
echo ""
echo -e "${CYAN}----------------------------------------${NC}"

echo ""
mcp-scanner --log-level error \
    --analyzers "$ANALYZERS" \
    --format summary \
    behavioral "$SOURCE_PATH"

echo ""
echo -e "${GREEN}Scan complete.${NC}"
