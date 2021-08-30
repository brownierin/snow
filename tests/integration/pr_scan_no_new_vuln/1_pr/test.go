package testunsafe

import (
	"os/exec"
)

func unsafeStaticCommand(cmd string) error {
	cmd := exec.Command("bash", "-c", cmd)
	return nil
}

func main() {

}
