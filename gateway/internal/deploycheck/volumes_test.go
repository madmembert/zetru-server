package deploycheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Named volumes are shared between containers that run as different users. Docker gives an empty
// named volume the owner of the mount directory of whichever container mounts it first, so every
// image that creates the directory must create it with the owner of the volume's writer. Before
// this test the analyzer and inference images created /feeds and /models as root; when the
// analyzer won the race the updater crashed with "Permission denied: '/feeds/psl'" and no feed
// was ever published (found on the first Docker Desktop run, 2026-11-27).
var sharedVolumeWriter = map[string]string{
	"/feeds":  "10005:10005", // updater writes, analyzer reads
	"/models": "10005:10005", // updater writes, inference reads
}

var imageDirs = []string{"analyzer", "inference", "updater"}

func TestSharedVolumeDirectoriesAreOwnedByTheirWriter(t *testing.T) {
	for _, image := range imageDirs {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", image, "Dockerfile"))
		if err != nil {
			t.Fatal(err)
		}
		// One entry per Dockerfile instruction: continuation lines (ending in a backslash) are joined.
		instruction := regexp.MustCompile(`\\\n`).ReplaceAllString(string(data), " ")
		for _, line := range strings.Split(instruction, "\n") {
			for dir, owner := range sharedVolumeWriter {
				mkdir := regexp.MustCompile(`mkdir -p[^&]*\s` + regexp.QuoteMeta(dir) + `(\s|$)`)
				if !mkdir.MatchString(line) {
					continue
				}
				chown := regexp.MustCompile(`chown ` + regexp.QuoteMeta(owner) + `[^&]*\s` + regexp.QuoteMeta(dir) + `(\s|$)`)
				if !chown.MatchString(line) {
					t.Errorf("%s/Dockerfile creates %s without `chown %s %s` in the same instruction: %q", image, dir, owner, dir, strings.TrimSpace(line))
				}
			}
		}
	}
}
