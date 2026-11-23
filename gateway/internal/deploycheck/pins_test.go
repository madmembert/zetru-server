package deploycheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Files whose image references must be pinned (GO-06): every service image, the deployment
// script and the README. deploy/pin-images.sh check covers the same files.
var pinnedFiles = []string{
	"gateway/Dockerfile",
	"lookup/Dockerfile",
	"analyzer/Dockerfile",
	"inference/Dockerfile",
	"updater/Dockerfile",
	"deploy/resolver/Dockerfile",
	"deploy/zetru-server",
	"README.md",
}

var (
	digest     = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	syntaxLine = regexp.MustCompile(`^#\s*syntax=(\S+)`)
	argImage   = regexp.MustCompile(`^ARG [A-Z0-9_]*IMAGE=(\S+)`)
	fromLine   = regexp.MustCompile(`^FROM\s+(?:--\S+\s+)*(\S+)(?:\s+(?:AS|as)\s+(\S+))?`)
	baseToken  = regexp.MustCompile(`(?:alpine|busybox|python|golang|debian|ubuntu|gcr\.io/distroless/[a-z0-9-]+):[A-Za-z0-9._-]+(?:@sha256:[0-9a-f]+)?`)
	apkAdd     = regexp.MustCompile(`apk add\s+([^\\&]*)`)
)

// TestImagesAndPackagesArePinned is the regression test for GO-06: every base image, the
// Dockerfile frontend and the image used for backup and restore carry a digest, and every apk
// package a version.
func TestImagesAndPackagesArePinned(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	for _, name := range pinnedFiles {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		stages := map[string]bool{}
		checked := 0
		for i, line := range strings.Split(string(data), "\n") {
			var refs []string
			switch {
			case syntaxLine.MatchString(line):
				refs = append(refs, syntaxLine.FindStringSubmatch(line)[1])
			case argImage.MatchString(line):
				refs = append(refs, argImage.FindStringSubmatch(line)[1])
			case fromLine.MatchString(line):
				m := fromLine.FindStringSubmatch(line)
				if !strings.HasPrefix(m[1], "$") && !stages[m[1]] {
					refs = append(refs, m[1])
				}
				if m[2] != "" {
					stages[m[2]] = true
				}
			default:
				refs = baseToken.FindAllString(line, -1)
			}
			for _, ref := range refs {
				checked++
				if !digest.MatchString(ref) {
					t.Errorf("%s:%d: image %q is not pinned by digest", name, i+1, ref)
				}
			}
			if m := apkAdd.FindStringSubmatch(line); m != nil {
				for _, pkg := range strings.Fields(m[1]) {
					if !strings.HasPrefix(pkg, "-") && !strings.Contains(pkg, "=") {
						t.Errorf("%s:%d: apk package %q has no version", name, i+1, pkg)
					}
				}
			}
		}
		if checked == 0 {
			t.Errorf("%s: no image reference found (the check would pass vacuously)", name)
		}
	}
}
