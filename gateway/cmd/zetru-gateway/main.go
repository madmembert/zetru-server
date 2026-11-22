// Command zetru-gateway is the public, TLS-terminating gateway of the Zetru analysis server
// (concept §3.2, §4, §11) and its operator CLI.
//
//	zetru-gateway serve
//	zetru-gateway init --name <name> --url https://host:8443 [--url …] [--tenant <name>]
//	zetru-gateway pair --tenant <name> [--create]
//	zetru-gateway devices [--tenant <name>]
//	zetru-gateway revoke <device-id>
//	zetru-gateway rotate-tls [--complete | --activate-backup]
//	zetru-gateway tenant list | create <name> | delete <name> --yes | policy <name> [flags]
//	zetru-gateway set-urls --url https://… [--url …]
//	zetru-gateway healthcheck
//
// The data directory is $ZETRU_DATA_DIR (default /data) or --data.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const version = "1.0.0"

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: zetru-gateway <command> [flags]

Commands:
  serve              run the gateway (TLS 1.3 on $ZETRU_LISTEN, default :8443)
  init               create keys, the server configuration, the first tenant and a pairing code
  pair               print a new single-use pairing code (valid 10 minutes) for a tenant
  devices            list paired devices
  revoke <id>        revoke a device immediately
  rotate-tls         start a planned TLS key rotation (--complete, --activate-backup)
  tenant             list | create <name> | delete <name> --yes | policy <name> [flags]
  set-urls           replace the server URLs written into new pairing codes
  healthcheck        check the running gateway (used by the container healthcheck)

Every command accepts --data <dir> (default $ZETRU_DATA_DIR or /data).
`)
}

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "init":
		err = cmdInit(args)
	case "pair":
		err = cmdPair(args)
	case "devices":
		err = cmdDevices(args)
	case "revoke":
		err = cmdRevoke(args)
	case "rotate-tls":
		err = cmdRotateTLS(args)
	case "tenant":
		err = cmdTenant(args)
	case "set-urls":
		err = cmdSetURLs(args)
	case "healthcheck":
		err = cmdHealthcheck(args)
	case "help", "-h", "--help":
		usage(os.Stdout)
		return
	default:
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}

// dataDirFlag registers --data on fs.
func dataDirFlag(fs *flag.FlagSet) *string {
	def := os.Getenv("ZETRU_DATA_DIR")
	if def == "" {
		def = "/data"
	}
	return fs.String("data", def, "data directory")
}

// multiFlag collects repeated string flags.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// parseInterspersed parses flags that may appear before or after positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}
