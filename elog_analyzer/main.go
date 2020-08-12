package main
import (
	"fmt"
	"flag"
	"encoding/json"
	"os"
	"io/ioutil"
	"github.com/cshari-zededa/eve-tpm2-tools/eventlog"
)

var (
	parseLog bool
	verbose  bool
	deriveTemplate bool
	validate bool
	templatePath string
	eventLogPath string
)
func init() {
    flag.BoolVar(&parseLog, "parse-log", false, "Decode and print details from eventlog")
    flag.BoolVar(&verbose, "verbose", false, "Display details of event data")
    flag.BoolVar(&deriveTemplate, "derive-template", false, "Derive a template out of given eventlog")
    flag.BoolVar(&validate, "validate-eventlog", false, "Validate eventlog against a given template")
    flag.StringVar(&templatePath, "template-file-path", "", "Path to template file")
    flag.StringVar(&eventLogPath, "eventlog-file-path", "", "Path to eventlog file")
}


func main() {
	flag.Parse()
	fmt.Println(eventLogPath)
	if deriveTemplate {
		events, err := eventlog.ParseEvents(eventLogPath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		template    := eventlog.PrepareMeasurements(events)
		buf, err    := json.MarshalIndent(template, "", "\t")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(ioutil.WriteFile(templatePath, buf, 755))
		return
	}
 	if validate {
		events, err := eventlog.ParseEvents(eventLogPath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		buf, err := ioutil.ReadFile(templatePath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		template := make([]eventlog.TemplateEvent, 0)
		err = json.Unmarshal(buf, &template)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		pcrs := eventlog.EventLogIterate(events)
		err = eventlog.ValidateEventLog(events, pcrs, template)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			fmt.Println("Validation successful!")
			return
		}
	}
	if parseLog {
		events, err := eventlog.ParseEvents(eventLogPath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		eventlog.DumpEventLog(events, verbose)
		return
	}
}
