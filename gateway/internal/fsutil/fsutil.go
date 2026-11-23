//go:build unix

// Package fsutil provides crash-safe file writes and cross-process locks for the gateway's
// persistent state (registry, keys, counters). The gateway CLI and the running server share the
// same data directory, so every read-modify-write cycle is serialised with an advisory lock.
package fsutil

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// WriteFileAtomic writes data to path via a temporary file in the same directory, fsyncs it,
// renames it over path and fsyncs the directory. Readers see either the old or the new content,
// never a partial file. The file mode is perm (0600 for everything the gateway stores).
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	return WriteStreamAtomic(path, perm, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// WriteStreamAtomic is WriteFileAtomic for content produced by write, which receives a buffered
// writer on the temporary file. Large state is written this way without building it in memory.
func WriteStreamAtomic(path string, perm os.FileMode, write func(w io.Writer) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	bw := bufio.NewWriterSize(tmp, 64<<10)
	if err := write(bw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := bw.Flush(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	committed = true
	return SyncDir(dir)
}

// SyncDir fsyncs a directory so that a preceding rename is durable.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

// RemoveIfExists deletes path and ignores a missing file. It is used for files that must not
// outlive their retention period (concept §14.2), such as state files from older versions.
func RemoveIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Lock is an exclusive advisory lock held on a lock file.
type Lock struct {
	f *os.File
}

// LockFile blocks until it holds an exclusive flock on path (created with mode 0600 if missing).
func LockFile(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Lock{f: f}, nil
}

// Unlock releases the lock.
func (l *Lock) Unlock() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}

// Stamp identifies one version of a file (inode, size, modification time). An atomic rename always
// produces a new inode, so a changed stamp means the file was replaced.
type Stamp struct {
	Ino   uint64
	Size  int64
	MTime int64
	Valid bool
}

// StatStamp returns the stamp of path; a missing file yields a zero (invalid) stamp and no error.
func StatStamp(path string) (Stamp, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Stamp{}, nil
	}
	if err != nil {
		return Stamp{}, err
	}
	s := Stamp{Size: info.Size(), MTime: info.ModTime().UnixNano(), Valid: true}
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		s.Ino = uint64(sys.Ino)
	}
	return s, nil
}
