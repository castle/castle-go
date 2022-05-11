//go:build mage
// +build mage

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/sh"
)

// Test tests all go code in the current directory and
// all subdirectories
func Test() error {
	return sh.RunV("go", "test", "./...")
}

func Install() error {
	return sh.RunV("go", "get", "-t", "./...")
}

// Lint runs code linters on current directory and all
// subdirectories
func Lint() error {
	linter := sh.OutCmd(filepath.Join(repoRoot(), "bin", "golangci-lint"))
	version := "1.39.0"

	currentVersion, err := linter("--version")
	if err != nil || !strings.Contains(currentVersion, version) {
		fmt.Println("linter binary outdated or missing, downloading a new one now")
		err := updateLinter(version)
		if err != nil {
			return err
		}
	}

	out, err := linter("run", "--deadline=2m", "--config="+repoRoot()+"/.golangci.yml", "./...")
	if out != "" {
		fmt.Println(out)
	}
	return err
}

func updateLinter(version string) error {
	return sh.Run("bash", "-c",
		"curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b "+
			repoRoot()+"/bin v"+version,
	)
}

func repoRoot() string {
	path, err := sh.Output("git", "rev-parse", "--show-toplevel")
	if err != nil {
		panic(err)
	}

	return path
}

func gitSummary() string {
	summary, err := sh.Output("git", "describe", "--tags", "--dirty", "--always")
	if err != nil {
		panic(err)
	}

	return summary
}

func gitBranch() string {
	branch, err := sh.Output("git", "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		panic(err)
	}

	return branch
}

func gitHash() string {
	hash, err := sh.Output("git", "rev-parse", "HEAD")
	if err != nil {
		panic(err)
	}

	return hash
}
