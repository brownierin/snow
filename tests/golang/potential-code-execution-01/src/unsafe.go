package testunsafe

import (
	"context"
	"os/exec"
	"time"
)

func unsafeStaticCommand(cmd string) error {
	cmd := exec.Command("bash", "-c", cmd)

	return nil
}

func unsafeStaticCommandWithContext(cmd string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", cmd)
	stdout, err := cmd.Output()

	return nil
}