# vulnerabilities-fix-agent

A simple Agentic AI tool that scans, reports, and safely fixes vulnerable dependencies in **Go** and **Java** projects.

Built with **Google ADK for Go** + **Gemini** + **OSV-Scanner**.

## Features

- Scans `go.mod` and `build.gradle` for vulnerabilities
- Generates clear vulnerability reports
- Suggests and applies safe upgrades
- Shows changes before applying (diff)
- Requires your confirmation before fixing
- Re-scans and shows improvement

## Quick Start

1. Install OSV-Scanner:
   ```bash
   go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest

2. Set your API key:
   ```bash
   export GEMINI_API_KEY="your_gemini_api_key"

3. Run the agent:
   ```bash
   go run main.go