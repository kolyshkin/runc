package rawexec

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

func TestExecBinary(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing")
	mkdir := func(name string) string {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	// The prog in noexec is not executable, and in isdir is a directory.
	noexec, isdir, good := mkdir("noexec"), mkdir("isdir"), mkdir("good")
	if err := os.WriteFile(filepath.Join(noexec, "prog"), []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(isdir, "prog"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\necho \"$0 $* $FOO\" > \"$OUT\"\n"
	if err := os.WriteFile(filepath.Join(good, "prog"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "out")
	env := []string{"FOO=bar", "OUT=" + out}
	notFound := `exec: "prog": executable file not found in $PATH`

	for _, tc := range []struct {
		desc       string
		name, path string
		want       string // Output of a successful run.
		op         string // Failed op.
		errno      unix.Errno
	}{
		{
			desc: "lookup",
			name: "prog",
			path: strings.Join([]string{missing, noexec, isdir, good}, ":"),
			want: filepath.Join(good, "prog") + " a b bar",
		},
		{desc: "not found", name: "prog", path: strings.Join([]string{missing, noexec, isdir}, ":"), op: notFound, errno: unix.ENOENT},
		{desc: "empty PATH", name: "prog", path: "", op: notFound, errno: unix.ENOENT},
		// With a slash in the name, no lookup is performed.
		{desc: "slash", name: filepath.Join(good, "prog"), path: noexec, want: filepath.Join(good, "prog") + " a b bar"},
		{desc: "slash not executable", name: filepath.Join(noexec, "prog"), path: good, op: "exec " + strconv.Quote(filepath.Join(noexec, "prog")), errno: unix.EACCES},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			_ = os.Remove(out)
			var p rawfork.Program
			if err := execBinary(&p, tc.name, []string{"prog", "a", "b"}, env, tc.path); err != nil {
				t.Fatal(err)
			}
			proc, err := p.Start()
			if err != nil {
				t.Fatal(err)
			}
			err = proc.Wait()
			if tc.op != "" {
				var serr *os.SyscallError
				if !errors.As(err, &serr) || serr.Syscall != tc.op || !errors.Is(err, tc.errno) {
					t.Fatalf("want %s %v error, got %v", tc.op, tc.errno, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want+"\n" {
				t.Fatalf("want output %q, got %q", tc.want, got)
			}
		})
	}
}

func TestExecBinaryRelativePath(t *testing.T) {
	for _, path := range []string{"bin:/usr/bin", "/usr/bin::/bin", "/usr/bin:."} {
		var p rawfork.Program
		if err := execBinary(&p, "true", []string{"true"}, nil, path); !errors.Is(err, ErrUnsupported) {
			t.Errorf("PATH=%s: want unsupported error, got %v", path, err)
		}
	}
	// No lookup, so PATH does not matter.
	var p rawfork.Program
	if err := execBinary(&p, "./true", []string{"true"}, nil, "bin"); err != nil {
		t.Errorf("want no error, got %v", err)
	}
}
