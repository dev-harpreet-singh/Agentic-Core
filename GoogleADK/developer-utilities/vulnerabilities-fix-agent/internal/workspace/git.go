package workspace

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// EnsureWorkingDir checks if the path is a file or dir, returning the dir.
func EnsureWorkingDir(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return path
	}
	if !info.IsDir() && filepath.Base(path) == "go.mod" {
		return filepath.Dir(path)
	}
	return path
}

// Isolate creates a temporary branch for the agent to work in.
// It returns a cleanup function that MUST be deferred.
func Isolate(targetDir string) (func(), error) {
	// If the target path is not a git repository, skip isolation and continue.
	checkRepo := exec.Command("git", "rev-parse", "--is-inside-work-tree")
	checkRepo.Dir = targetDir
	if err := checkRepo.Run(); err != nil {
		fmt.Println("[Workspace] Target path is not a git repository. Skipping workspace isolation.")
		return func() {}, nil
	}

	// Create sandbox branch in the git repository.
	branchName := fmt.Sprintf("agentic-core/audit-%d", time.Now().Unix())
	fmt.Printf("[Workspace] Creating isolated branch: %s\n", branchName)

	checkoutCmd := exec.Command("git", "checkout", "-b", branchName)
	checkoutCmd.Dir = targetDir
	if err := checkoutCmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to create sandbox branch: %v", err)
	}

	// 3. Return the cleanup/teardown function
	cleanup := func() {
		fmt.Println("[Workspace] Agent finished. Leaving sandbox branch intact for human review.")
		// In a fully automated CI pipeline, you might push this branch or delete it if it failed.
		// For a local utility, leaving the user on the new branch with the fixes is optimal.
	}

	return cleanup, nil
}
