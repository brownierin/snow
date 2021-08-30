package testunsafe

import (
	"fmt"
	"io/ioutil"
	"os/exec"
)

func unsafeStaticCommand(cmd string) error {
	cmd := exec.Command("bash", "-c", cmd)
	return nil
}

func main() {
	// ruleid:bad-tmp-file-creation
	err := ioutil.WriteFile("/tmp/demo2", []byte("This is some data"), 0644)
	if err != nil {
		fmt.Println("Error while writing!")
	}
}
