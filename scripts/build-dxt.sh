#!/usr/bin/env bash

# Build script for creating DXT packages for mcp-ssh.
# This script creates .dxt files for distribution without committing them.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Building MCP SSH DXT Package${NC}"

if ! command -v npx >/dev/null 2>&1; then
  echo -e "${RED}Error: npm/npx not found. Please install Node.js.${NC}"
  exit 1
fi

if ! npm list @anthropic-ai/dxt >/dev/null 2>&1; then
  echo -e "${RED}Error: @anthropic-ai/dxt not found. Please run 'npm install'.${NC}"
  exit 1
fi

VERSION=$(npm pkg get version | tr -d '"')
BUILD_DIR="build"
STAGE_DIR="$BUILD_DIR/dxt-stage"
DXT_FILE="mcp-ssh-${VERSION}.dxt"
DXT_PATH="$BUILD_DIR/$DXT_FILE"

rm -rf "$BUILD_DIR"
mkdir -p "$STAGE_DIR"

echo -e "${YELLOW}Preparing DXT staging directory...${NC}"

cp package.json package-lock.json manifest.json server.mjs CHANGELOG.md LICENSE "$STAGE_DIR/"
cp -R bin src "$STAGE_DIR/"
cp -R docs "$STAGE_DIR/"
find "$STAGE_DIR/src" -name "*.test.mjs" -delete

echo -e "${YELLOW}Installing production dependencies...${NC}"
(cd "$STAGE_DIR" && npm install --omit=dev --omit=optional --ignore-scripts)

echo -e "${YELLOW}Creating DXT package...${NC}"
node node_modules/@anthropic-ai/dxt/dist/cli/cli.js pack "$STAGE_DIR" "$DXT_PATH"

rm -rf "$STAGE_DIR"

echo -e "${GREEN}DXT package created successfully: $DXT_PATH${NC}"
echo -e "${GREEN}Package size: $(ls -lh "$DXT_PATH" | awk '{print $5}')${NC}"

echo -e "\n${YELLOW}Next steps:${NC}"
echo "1. Test the DXT package locally"
echo "2. Upload to GitHub releases:"
echo "   gh release create v${VERSION} $DXT_PATH --title 'Release v${VERSION}' --notes 'MCP SSH Agent v${VERSION}'"
echo "3. Or upload manually to GitHub releases page"
