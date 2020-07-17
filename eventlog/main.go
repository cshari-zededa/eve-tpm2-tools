package main
import (
	"fmt"
)

func main() {
	events, err := ParseEvents("binary_bios_measurements")
	if err != nil {
		fmt.Println(err)
	} else {
		dumpEventLog(events)
	}
	return
}
