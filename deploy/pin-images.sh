#!/bin/sh
# pin-images.sh: keep the server's container inputs pinned (GO-06).
#
#   ./pin-images.sh check  [file ...]   exit 1 if an image reference has no @sha256 digest or an
#                                       apk package has no =version (offline; for CI)
#   ./pin-images.sh update [file ...]   resolve every image tag to its current digest and every
#                                       pinned apk package to the current version of its Alpine
#                                       branch, rewrite the files, then run check
#
# Without file arguments it works on all Dockerfiles of this repository, deploy/zetru-server and
# README.md. References look like name:tag@sha256:<digest>; update keeps the tag and
# replaces the digest. Registries: Docker Hub (registry-1.docker.io, anonymous token from
# auth.docker.io), gcr.io (anonymous); packages: dl-cdn.alpinelinux.org. Needs curl, sed, awk, tar.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
server="$(cd "$here/.." && pwd)"

default_files() {
  for f in "$server"/*/Dockerfile "$server"/deploy/*/Dockerfile "$server/deploy/zetru-server" "$server/README.md"; do
    [ -f "$f" ] && printf '%s\n' "$f"
  done
}

# Image references the check looks at: the Dockerfile frontend, ARG ..._IMAGE defaults, FROM lines
# that name an image directly, and name:tag tokens of known base images in scripts and docs.
image_refs() { # $1 = file; prints "line<TAB>reference"
  awk '
    /^# *syntax=/ { sub(/^# *syntax=/, ""); print NR "\t" $0; next }
    /^ARG [A-Z0-9_]*IMAGE=/ { sub(/^ARG [A-Z0-9_]*IMAGE=/, ""); print NR "\t" $0; next }
    /^FROM / {
      for (i = 2; i <= NF; i++) { if ($i ~ /^--/) continue; ref = $i; break }
      if (ref !~ /^\$/ && !(ref in stages)) print NR "\t" ref
      if ($(NF-1) == "AS" || $(NF-1) == "as") stages[$NF] = 1
      next
    }
    {
      line = $0
      while (match(line, /(alpine|busybox|python|golang|debian|ubuntu|gcr\.io\/distroless\/[a-z0-9-]+):[A-Za-z0-9._-]+(@sha256:[0-9a-f]+)?/)) {
        print NR "\t" substr(line, RSTART, RLENGTH)
        line = substr(line, RSTART + RLENGTH)
      }
    }' "$1"
}

check() {
  bad=0
  for f in "$@"; do
    refs="$(image_refs "$f")"
    if [ -n "$refs" ]; then
      while IFS="$(printf '\t')" read -r n ref; do
        if ! printf '%s\n' "$ref" | grep -Eq '@sha256:[0-9a-f]{64}$'; then
          echo "unpinned image: $f:$n: $ref" >&2
          bad=1
        fi
      done <<EOF
$refs
EOF
    fi
    # apk add: every package needs =version.
    pkgs="$(awk '/apk add/ { sub(/.*apk add/, ""); sub(/\\.*$/, ""); sub(/&&.*/, ""); n = split($0, a, " ");
                 for (i = 1; i <= n; i++) if (a[i] !~ /^-/) print NR "\t" a[i] }' "$f")"
    if [ -n "$pkgs" ]; then
      while IFS="$(printf '\t')" read -r n pkg; do
        case "$pkg" in
          *=*) ;;
          *) echo "unpinned apk package: $f:$n: $pkg" >&2; bad=1 ;;
        esac
      done <<EOF
$pkgs
EOF
    fi
  done
  [ "$bad" -eq 0 ] && echo "pin-images: all image references and packages are pinned"
  return "$bad"
}

accept='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'

digest_of() { # $1 = name:tag (without digest); prints sha256:...
  name="${1%:*}"; tag="${1##*:}"
  case "$name" in
    gcr.io/*)
      path="${name#gcr.io/}"
      curl -fsSI -m 30 -H "Accept: $accept" "https://gcr.io/v2/$path/manifests/$tag" ;;
    *)
      case "$name" in */*) repo="$name" ;; *) repo="library/$name" ;; esac
      token="$(curl -fsS -m 30 "https://auth.docker.io/token?service=registry.docker.io&scope=repository:$repo:pull" |
        sed -n 's/.*"token" *: *"\([^"]*\)".*/\1/p')"
      curl -fsSI -m 30 -H "Authorization: Bearer $token" -H "Accept: $accept" \
        "https://registry-1.docker.io/v2/$repo/manifests/$tag" ;;
  esac | tr -d '\r' | awk -F': ' 'tolower($1) == "docker-content-digest" { print $2 }'
}

apk_version() { # $1 = branch (v3.22), $2 = package; prints the version in main (x86_64 and aarch64 must agree)
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/pin-images.XXXXXX")" || return 1
  versions=""
  for arch in x86_64 aarch64; do
    curl -fsS -m 60 -o "$tmp/idx.tar.gz" "https://dl-cdn.alpinelinux.org/alpine/$1/main/$arch/APKINDEX.tar.gz" &&
      tar -xzf "$tmp/idx.tar.gz" -C "$tmp" APKINDEX || { rm -rf "$tmp"; return 1; }
    versions="$versions $(awk -v p="$2" 'BEGIN { RS = ""; FS = "\n" }
      { name = ""; ver = ""; for (i = 1; i <= NF; i++) { if ($i ~ /^P:/) name = substr($i, 3); if ($i ~ /^V:/) ver = substr($i, 3) }
        if (name == p) print ver }' "$tmp/APKINDEX")"
  done
  rm -rf "$tmp"
  set -- $versions
  [ $# -eq 2 ] && [ "$1" = "$2" ] || { echo "pin-images: no single version of $2 in $1 ($versions)" >&2; return 1; }
  echo "$1"
}

# replace_token FILE FROM TO replaces FROM where it is a whole reference (not followed by more
# reference characters), keeping the file's mode.
replace_token() {
  awk -v from="$2" -v to="$3" '{
      out = ""; line = $0
      while ((i = index(line, from)) > 0) {
        next_char = substr(line, i + length(from), 1)
        out = out substr(line, 1, i - 1) (next_char ~ /[A-Za-z0-9._@:-]/ ? from : to)
        line = substr(line, i + length(from))
      }
      print out line
    }' "$1" > "$1.pin-tmp"
  cat "$1.pin-tmp" > "$1"
  rm -f "$1.pin-tmp"
}

update() {
  for f in "$@"; do
    refs="$(image_refs "$f" | cut -f2 | sort -u)"
    for ref in $refs; do
      base="${ref%@*}"
      case "$base" in *:*) ;; *) echo "pin-images: $f: $ref has no tag, skipped" >&2; continue ;; esac
      digest="$(digest_of "$base")" || digest=""
      case "$digest" in sha256:*) ;; *) echo "pin-images: cannot resolve $base" >&2; return 1 ;; esac
      if [ "$ref" != "$base@$digest" ]; then
        replace_token "$f" "$ref" "$base@$digest"
        echo "$f: $base -> $digest"
      fi
    done
    # apk packages pinned as name=version in a Dockerfile whose base image is alpine:<x.y.z>.
    branch="$(sed -n 's/^ARG [A-Z0-9_]*IMAGE=alpine:\([0-9]*\.[0-9]*\).*/v\1/p' "$f" | head -n 1)"
    [ -n "$branch" ] || continue
    for current in $(awk '/apk add/ { sub(/.*apk add/, ""); sub(/\\.*$/, ""); sub(/&&.*/, ""); n = split($0, a, " ");
                       for (i = 1; i <= n; i++) if (a[i] !~ /^-/) print a[i] }' "$f"); do
      pkg="${current%%=*}"
      ver="$(apk_version "$branch" "$pkg")" || return 1
      [ -n "$ver" ] || { echo "pin-images: no version for $pkg" >&2; return 1; }
      if [ "$current" != "$pkg=$ver" ]; then
        replace_token "$f" "$current" "$pkg=$ver"
        echo "$f: $current -> $pkg=$ver"
      fi
    done
  done
}

cmd="${1:-check}"
[ $# -gt 0 ] && shift
if [ $# -eq 0 ]; then
  set -- $(default_files)
fi
case "$cmd" in
  check) check "$@" ;;
  update)
    update "$@" || { echo "pin-images: update failed; check the files before committing" >&2; exit 1; }
    check "$@" ;;
  *) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
