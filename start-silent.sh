#!/bin/bash

# Change to the directory where this script is located
cd "$(dirname "$0")"

# MCP SSH Agent Silent Startup Script
# This script starts the MCP SSH server in silent mode for MCP clients
# No debug output will be shown, only clean JSON communication

export MCP_SILENT=true
exec node server.mjs
