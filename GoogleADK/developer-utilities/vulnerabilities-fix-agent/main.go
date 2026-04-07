package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	// Internal Workspace & Tools
	"github.com/dev-harpreet-singh/Agentic-Core/internal/tools"
	"github.com/dev-harpreet-singh/Agentic-Core/internal/workspace"

	// Google ADK 1.0.0 Standard Imports
	"google.golang.org/adk/agent"
	"google.golang.org/adk/agent/llmagent"
	"google.golang.org/adk/model"
	"google.golang.org/adk/model/gemini"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/session"
	"google.golang.org/adk/tool"
	"google.golang.org/adk/tool/functiontool"
	"google.golang.org/genai"
)

func initGeminiModel(ctx context.Context, apiKey string) (model.LLM, error) {
	modelName := "gemini-2.5-pro"

	if envModel := os.Getenv("GEMINI_MODEL"); envModel != "" {
		modelName = envModel
	}

	fmt.Printf("[System] Initializing Gemini model: %s\n", modelName)
	return gemini.NewModel(ctx, modelName, &genai.ClientConfig{APIKey: apiKey})
}

func main() {
	ctx := context.Background()

	// 1. Load System Prompts
	spec, err := os.ReadFile("spec.md")
	if err != nil {
		log.Fatal("FATAL: spec.md missing. System cannot boot without instructions.")
	}

	// 2. Boot Gemini (Requires GOOGLE_API_KEY env var)
	apiKey := os.Getenv("GOOGLE_API_KEY")
	if apiKey == "" {
		log.Fatal("FATAL: GOOGLE_API_KEY environment variable is not set.")
	}

	m, err := initGeminiModel(ctx, apiKey)
	if err != nil {
		log.Fatalf("FATAL: Failed to initialize AI model: %v", err)
	}

	// 3. Register Capabilities (Strict tool.Tool interface)
	t1, err := functiontool.New(functiontool.Config{Name: "scan_vulnerabilities"}, tools.ScanVulnerabilities)
	if err != nil {
		log.Fatal(err)
	}
	t2, err := functiontool.New(functiontool.Config{Name: "generate_vulnerability_csv"}, tools.GenerateVulnerabilityCSV)
	if err != nil {
		log.Fatal(err)
	}
	t3, err := functiontool.New(functiontool.Config{Name: "apply_fixes"}, tools.ApplyFixes)
	if err != nil {
		log.Fatal(err)
	}
	t4, err := functiontool.New(functiontool.Config{Name: "generate_post_fix_csv"}, tools.GeneratePostFixCSV)
	if err != nil {
		log.Fatal(err)
	}
	t5, err := functiontool.New(functiontool.Config{Name: "validate_build"}, tools.ValidateBuild)
	if err != nil {
		log.Fatal(err)
	}
	t6, err := functiontool.New(functiontool.Config{Name: "install_osv_scanner"}, tools.InstallOSVScanner)
	if err != nil {
		log.Fatal(err)
	}
	t7, err := functiontool.New(functiontool.Config{Name: "scan_with_osv"}, tools.ScanWithOSVScanner)
	if err != nil {
		log.Fatal(err)
	}
	t8, err := functiontool.New(functiontool.Config{Name: "generate_osv_csv"}, tools.GenerateOSVCSV)
	if err != nil {
		log.Fatal(err)
	}

	agentTools := []tool.Tool{t1, t2, t3, t4, t5, t6, t7, t8}

	// 4. Initialize Agent
	secAgent, err := llmagent.New(llmagent.Config{
		Name:        "Core_Auditor",
		Model:       m,
		Instruction: string(spec),
		Tools:       agentTools,
	})
	if err != nil {
		log.Fatalf("Failed to initialize Agent: %v", err)
	}

	// 5. Initialize the Runner (Handles InvocationContext internally)
	r, err := runner.New(runner.Config{
		AppName:           "Agentic-Core",
		Agent:             secAgent,
		SessionService:    session.InMemoryService(),
		AutoCreateSession: true,
	})

	if err != nil {
		log.Fatalf("Failed to initialize Runner: %v", err)
	}

	// 6. Interactive Execution Loop
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("=== Agentic-Core Vulnerability Auditor ===")

	for {
		fmt.Print("\n[Target] Enter project path (or 'exit'): ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "exit" {
			break
		}

		targetDir := workspace.EnsureWorkingDir(input)

		// Workspace Isolation
		cleanup, err := workspace.Isolate(targetDir)
		if err != nil {
			fmt.Printf("[System Error]: %v\n", err)
			continue
		}

		fmt.Println("[System] Workspace isolated. Engaging AI Agent...")

		// Execute using the Runner's streamlined Run method
		prompt := fmt.Sprintf("Audit the Go project at: %s", targetDir)
		msg := genai.NewContentFromText(prompt, genai.RoleUser)

		// Runner takes (ctx, userID, sessionID, content, config)
		events := r.Run(ctx, "admin-user", "session-001", msg, agent.RunConfig{})

		// ADK 1.0 uses a standard (value, error) iterator for the stream
		for event, err := range events {
			if err != nil {
				fmt.Printf("\n[Agent Error]: %v\n", err)
				break
			}

			if event.Content != nil {
				role := strings.ToUpper(string(event.Content.Role))
				for _, part := range event.Content.Parts {
					if part.Text != "" {
						fmt.Printf("\n[%s]: %s\n", role, part.Text)
					}
				}
			}
		}

		cleanup()
	}
}
