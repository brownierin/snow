package testsafe

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"go.starlark.net/starlark"
)

func getKubeContexts(env string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", "kubectl config get-contexts -o name")
	stdout, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	contexts := make([]string, 0)
	lines := strings.Fields(string(stdout))
	for _, l := range lines {
		if strings.Contains(l, env) && !strings.Contains(l, "test") {
			contexts = append(contexts, l)
		}
	}

	return contexts, nil
}

func safeStaticCommand() error {
	cmd := exec.Command("docker", "run", "-d", "--name", "mycontainer", "-p", "5000:5000", "softwaremill/elasticmq")

	return nil
}