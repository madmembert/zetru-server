package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"zetru.app/gateway/internal/config"
	"zetru.app/gateway/internal/keys"
	"zetru.app/gateway/internal/pairing"
	"zetru.app/gateway/internal/qr"
	"zetru.app/gateway/internal/registry"
)

var stdout io.Writer = os.Stdout

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := dataDirFlag(fs)
	name := fs.String("name", "", "server display name shown in the app (max 40 characters)")
	tenant := fs.String("tenant", "default", "name of the first tenant")
	qrMode := fs.String("qr", "ansi", "QR rendering: ansi, plain or none")
	var urls multiFlag
	fs.Var(&urls, "url", "base URL the app uses, e.g. https://192.168.1.20:8443 (1-3, tried in order)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := config.Server{Version: 1, Name: *name, URLs: urls, Trust: "pin_only"}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if keys.Exists(*dir) {
		return errors.New("this data directory is already initialised; use pair to add devices")
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	now := time.Now()
	if err := keys.Init(*dir, cfg.Hosts(), now); err != nil {
		return err
	}
	if err := config.Save(*dir, cfg); err != nil {
		return err
	}
	reg, err := registry.Open(*dir, nil)
	if err != nil {
		return err
	}
	t, err := reg.CreateTenant(*tenant)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Initialised the Zetru gateway in %s.\nBack up this directory (it holds the server keys); keep backup/ offline if you can.\n\n", *dir)
	return printPairing(*dir, reg, t, *qrMode)
}

func cmdPair(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	dir := dataDirFlag(fs)
	tenantName := fs.String("tenant", "", "tenant name (required)")
	create := fs.Bool("create", false, "create the tenant if it does not exist")
	qrMode := fs.String("qr", "ansi", "QR rendering: ansi, plain or none")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenantName == "" {
		return errors.New("--tenant is required")
	}
	reg, err := registry.Open(*dir, nil)
	if err != nil {
		return err
	}
	t, err := reg.TenantByName(*tenantName)
	if errors.Is(err, registry.ErrUnknownTenant) && *create {
		t, err = reg.CreateTenant(*tenantName)
	}
	if err != nil {
		return fmt.Errorf("tenant %q: %w (use --create to add it)", *tenantName, err)
	}
	return printPairing(*dir, reg, t, *qrMode)
}

func printPairing(dir string, reg *registry.Registry, t registry.Tenant, qrMode string) error {
	if qrMode != "ansi" && qrMode != "plain" && qrMode != "none" {
		return errors.New("--qr must be ansi, plain or none")
	}
	cfg, err := config.Load(dir)
	if err != nil {
		return err
	}
	mat, err := keys.Load(dir)
	if err != nil {
		return err
	}
	token, expires, err := reg.CreateEnrolmentToken(t.ID, registry.TokenTTL)
	if err != nil {
		return err
	}
	payload := pairing.Payload{V: 1, URLs: cfg.URLs, Pins: mat.PinSet.Pins, Trust: cfg.Trust, SID: mat.IdentityPublic(),
		Tenant: t.ID, Token: token, Name: cfg.Name}
	link, err := payload.URI()
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Pairing code for tenant %q on server %q\n", t.Name, cfg.Name)
	fmt.Fprintf(stdout, "Single use, valid until %s UTC.\n\n", expires.UTC().Format("2006-01-02 15:04"))
	if qrMode != "none" {
		code, err := qr.Encode([]byte(link))
		if err != nil {
			return err
		}
		fmt.Fprint(stdout, code.Render(qrMode == "ansi"))
		fmt.Fprintln(stdout)
	}
	fmt.Fprintf(stdout, "Server identity fingerprint: %s\n", keys.ShortFingerprint(mat.Identity.Public().(ed25519.PublicKey)))
	fmt.Fprintln(stdout, "Confirm in the app only if it shows the same fingerprint.")
	fmt.Fprintf(stdout, "\nText code for manual pairing:\n%s\n", link)
	return nil
}

// clean removes control characters before printing operator-supplied or device-supplied text.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

func cmdDevices(args []string) error {
	fs := flag.NewFlagSet("devices", flag.ContinueOnError)
	dir := dataDirFlag(fs)
	tenantName := fs.String("tenant", "", "only this tenant")
	if err := fs.Parse(args); err != nil {
		return err
	}
	reg, err := registry.Open(*dir, nil)
	if err != nil {
		return err
	}
	names := map[string]string{}
	filter := ""
	for _, t := range reg.Tenants() {
		names[t.ID] = t.Name
		if t.Name == *tenantName {
			filter = t.ID
		}
	}
	if *tenantName != "" && filter == "" {
		return fmt.Errorf("unknown tenant %q", *tenantName)
	}
	devices := reg.Devices(filter)
	sort.Slice(devices, func(i, j int) bool { return devices[i].CreatedAt < devices[j].CreatedAt })
	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "DEVICE ID\tTENANT\tLABEL\tPAIRED\tLAST SEEN\tSTATUS")
	for _, d := range devices {
		status := "active"
		if d.Revoked() {
			status = "revoked " + time.Unix(d.RevokedAt, 0).UTC().Format("2006-01-02")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", d.ID, clean(names[d.TenantID]), clean(d.Label),
			time.Unix(d.CreatedAt, 0).UTC().Format("2006-01-02"), d.LastSeenDay, status)
	}
	return w.Flush()
}

func cmdRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	dir := dataDirFlag(fs)
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 || !registry.ValidUUID(positional[0]) {
		return errors.New("usage: revoke <device-id> (see the devices command)")
	}
	reg, err := registry.Open(*dir, nil)
	if err != nil {
		return err
	}
	if err := reg.Revoke(positional[0]); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Device %s revoked. The running gateway rejects it from the next request on.\n", positional[0])
	return nil
}

func cmdRotateTLS(args []string) error {
	fs := flag.NewFlagSet("rotate-tls", flag.ContinueOnError)
	dir := dataDirFlag(fs)
	complete := fs.Bool("complete", false, "finish a pending rotation now instead of after 30 days")
	backup := fs.Bool("activate-backup", false, "the primary key is lost: serve the backup key now and create a new backup")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*dir)
	if err != nil {
		return err
	}
	now := time.Now()
	switch {
	case *complete && *backup:
		return errors.New("choose one of --complete and --activate-backup")
	case *complete:
		err = keys.CompleteRotation(*dir, now)
	case *backup:
		err = keys.ActivateBackup(*dir, cfg.Hosts(), now)
	default:
		err = keys.StartRotation(*dir, cfg.Hosts(), now)
	}
	if err != nil {
		return err
	}
	mat, err := keys.Load(*dir)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Pin set %d published (apps fetch it with GET /v1/server/info):\n", mat.PinSet.Seq)
	for _, p := range mat.PinSet.Pins {
		fmt.Fprintf(stdout, "  %s\n", p)
	}
	switch {
	case mat.Rotation != nil:
		fmt.Fprintf(stdout, "The current key stays in use until %s UTC; then the new key is served automatically.\n",
			time.Unix(mat.Rotation.PromoteAfter, 0).UTC().Format("2006-01-02 15:04"))
		fmt.Fprintln(stdout, "Devices that do not contact the server before then must pair again.")
	case *backup:
		fmt.Fprintln(stdout, "The backup key is now served. A new backup key was written to backup/tls.pem; move it offline if you keep the backup offline.")
	default:
		fmt.Fprintln(stdout, "The new key is now served.")
	}
	return nil
}

func cmdSetURLs(args []string) error {
	fs := flag.NewFlagSet("set-urls", flag.ContinueOnError)
	dir := dataDirFlag(fs)
	var urls multiFlag
	fs.Var(&urls, "url", "base URL (1-3)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*dir)
	if err != nil {
		return err
	}
	cfg.URLs = urls
	if err := config.Save(*dir, cfg); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "URLs updated. New pairing codes carry them; already paired devices keep the URLs they were paired with.")
	return nil
}

func cmdTenant(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: tenant list | create <name> | delete <name> --yes | policy <name> [flags]")
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("tenant "+sub, flag.ContinueOnError)
	dir := dataDirFlag(fs)
	yes := fs.Bool("yes", false, "confirm deletion")
	backends := fs.String("backends", "", "comma-separated backend IDs, e.g. rules,encoder")
	dailyQuota := fs.Int("daily-quota", -1, "analyses per device and day (0 = profile default)")
	rate := fs.Int("rate", -1, "analyses per device and minute (0 = profile default)")
	maxMail := fs.Int("max-mail-bytes", -1, "maximum mail size in bytes (0 = 20 MiB default)")
	cross := fs.String("cross-tenant", "", "cross-tenant campaign counting: on or off")
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	reg, err := registry.Open(*dir, nil)
	if err != nil {
		return err
	}
	switch sub {
	case "list":
		w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TENANT ID\tNAME\tDEVICES\tBACKENDS\tDAILY QUOTA\tCROSS-TENANT")
		for _, t := range reg.Tenants() {
			active := 0
			for _, d := range reg.Devices(t.ID) {
				if !d.Revoked() {
					active++
				}
			}
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%v\n", t.ID, clean(t.Name), active, strings.Join(t.Policy.Backends, ","),
				orDefault(t.Policy.DailyQuota), t.Policy.CrossTenantCounting)
		}
		return w.Flush()
	case "create":
		if len(positional) != 1 {
			return errors.New("usage: tenant create <name>")
		}
		t, err := reg.CreateTenant(positional[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Tenant %q created (%s).\n", t.Name, t.ID)
		return nil
	case "delete":
		if len(positional) != 1 {
			return errors.New("usage: tenant delete <name> --yes")
		}
		t, err := reg.TenantByName(positional[0])
		if err != nil {
			return err
		}
		if !*yes {
			return fmt.Errorf("this removes tenant %q, all its devices and its counters; repeat with --yes", t.Name)
		}
		if err := reg.DeleteTenant(t.ID); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Tenant %q deleted. Its counters are purged by the running gateway within 5 minutes (or at its next start).\n", t.Name)
		return nil
	case "policy":
		if len(positional) != 1 {
			return errors.New("usage: tenant policy <name> [--backends …] [--daily-quota n] [--rate n] [--max-mail-bytes n] [--cross-tenant on|off]")
		}
		t, err := reg.TenantByName(positional[0])
		if err != nil {
			return err
		}
		p := t.Policy
		changed := false
		if *backends != "" {
			p.Backends = nil
			for _, b := range strings.Split(*backends, ",") {
				if b = strings.TrimSpace(b); b != "" {
					p.Backends = append(p.Backends, b)
				}
			}
			changed = true
		}
		for _, v := range []struct {
			val    int
			target *int
		}{{*dailyQuota, &p.DailyQuota}, {*rate, &p.RatePerMinute}, {*maxMail, &p.MaxMailBytes}} {
			if v.val >= 0 {
				*v.target, changed = v.val, true
			}
		}
		switch *cross {
		case "":
		case "on":
			p.CrossTenantCounting, changed = true, true
		case "off":
			p.CrossTenantCounting, changed = false, true
		default:
			return errors.New("--cross-tenant must be on or off")
		}
		if changed {
			if err := reg.SetPolicy(t.ID, p); err != nil {
				return err
			}
		}
		fmt.Fprintf(stdout, "Tenant %q policy:\n  backends: %s\n  daily quota: %s\n  rate per minute: %s\n  max mail bytes: %s\n  cross-tenant counting: %v\n",
			t.Name, strings.Join(p.Backends, ","), orDefault(p.DailyQuota), orDefault(p.RatePerMinute), orDefault(p.MaxMailBytes), p.CrossTenantCounting)
		return nil
	}
	return fmt.Errorf("unknown tenant command %q", sub)
}

func orDefault(v int) string {
	if v == 0 {
		return "profile default"
	}
	return strconv.Itoa(v)
}
