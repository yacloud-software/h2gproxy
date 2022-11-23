package srv

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

var (
	print_fds = flag.Bool("print_fds", false, "[USED FOR DEBUG] print open filedescriptors - debug, very verbose!")
	save_fds  = flag.Bool("save_fds", false, "[USED FOR DEBUG] save open filedescriptors to disk - very expensive and slow")
	fdsavectr = 0
)

//PrintOpenFDs will provided statistics on file descriptors that are currently open. Usually executed per http request
//USED FOR DEBUG ONLY!
func PrintOpenFDs() {
	if *save_fds {
		saveFDs()
	}
	if !*print_fds {
		return
	}
	pid := os.Getpid()
	fmt.Printf("pid %d - Open file descriptors: %d\n", pid, countOpenFiles())
}

func countOpenFiles() int {
	out, err := exec.Command("/bin/sh", "-c", fmt.Sprintf("lsof -p %v", os.Getpid())).Output()
	if err != nil {
		fmt.Printf("Failed to get open file descriptors: %s\n", err)
		return 0
	}
	lines := strings.Split(string(out), "\n")
	return len(lines) - 1
}
func saveFDs() {
	out, err := exec.Command("/bin/sh", "-c", fmt.Sprintf("lsof -p %v", os.Getpid())).Output()
	if err != nil {
		fmt.Printf("Failed to get open file descriptors: %s\n", err)
		return
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) < 40 {
		return
	}
	fdsavectr++
	ioutil.WriteFile(fmt.Sprintf("/tmp/fds/%d.txt", fdsavectr), []byte(out), 0666)
}
