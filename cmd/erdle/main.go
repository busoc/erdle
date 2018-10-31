package main

import (
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/midbel/cli"
)

var (
	GPS   = time.Date(1980, 1, 6, 0, 0, 0, 0, time.UTC)
	UNIX  = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	Delta = GPS.Sub(UNIX)
)

var commands = []*cli.Command{
	dumpCommand,
	relayCommand,
	replayCommand,
	countCommand,
	decodeCommand,
}

const helpText = `{{.Name}} reports various information about vcdu and/or hrdl packets

Usage:

  {{.Name}} command [options] <arguments>

Available commands:

{{range .Commands}}{{if .Runnable}}{{printf "  %-12s %s" .String .Short}}{{if .Alias}} (alias: {{ join .Alias ", "}}){{end}}{{end}}
{{end}}
Use {{.Name}} [command] -h for more information about its usage.
`

func init() {
	cli.Version = "0.0.1-alpha"
	cli.BuildTime = "2018-10-22 05:27:00 UTC"
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			log.Fatalf("unexpected error: %s", err)
		}
	}()
	sort.Slice(commands, func(i, j int) bool { return commands[i].String() < commands[j].String() })
	usage := func() {
		data := struct {
			Name     string
			Commands []*cli.Command
		}{
			Name:     filepath.Base(os.Args[0]),
			Commands: commands,
		}
		fs := map[string]interface{}{
			"join": strings.Join,
		}
		sort.Slice(data.Commands, func(i, j int) bool { return data.Commands[i].String() < data.Commands[j].String() })
		t := template.Must(template.New("help").Funcs(fs).Parse(helpText))
		t.Execute(os.Stderr, data)

		os.Exit(2)
	}
	if err := cli.Run(commands, usage, nil); err != nil {
		log.Fatalln(err)
	}
}

func protoFromAddr(a string) (string, string) {
	u, err := url.Parse(a)
	if err != nil {
		return "tcp", a
	}
	return strings.ToLower(u.Scheme), u.Host
}
