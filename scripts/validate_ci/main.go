package main

import (
	"log"
	"os"
	"os/exec"
)

func main() {
	if os.Getenv("CI") == "" {
		return // nothing to do outside CI
	}
	cmd := exec.Command("git", "diff", "--exit-code")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatalf("generation seems to have done something: %v", err)
	}
}
