package rawexec

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUserHome(t *testing.T) {
	const passwd = "root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000::/home/user:/bin/sh\n"
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, etc string)
		uid   int
		want  string
		err   bool
	}{
		{
			name: "found",
			setup: func(t *testing.T, etc string) {
				if err := os.WriteFile(filepath.Join(etc, "passwd"), []byte(passwd), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			uid: 1000, want: "/home/user",
		},
		{
			name: "not found",
			setup: func(t *testing.T, etc string) {
				if err := os.WriteFile(filepath.Join(etc, "passwd"), []byte(passwd), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			uid: 2000, want: "/",
		},
		{
			// The symlink is resolved inside the root.
			name: "absolute symlink",
			setup: func(t *testing.T, etc string) {
				if err := os.WriteFile(filepath.Join(etc, "passwd.real"), []byte(passwd), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/etc/passwd.real", filepath.Join(etc, "passwd")); err != nil {
					t.Fatal(err)
				}
			},
			uid: 0, want: "/root",
		},
		{
			name: "no passwd",
			uid:  0, want: "/", err: true,
		},
		{
			// Must not block.
			name: "fifo",
			setup: func(t *testing.T, etc string) {
				if err := unix.Mkfifo(filepath.Join(etc, "passwd"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			uid: 0, want: "/", err: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			etc := filepath.Join(dir, "etc")
			if err := os.Mkdir(etc, 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.setup != nil {
				tc.setup(t, etc)
			}
			root, err := os.OpenFile(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			home, err := UserHome(root, tc.uid)
			if (err != nil) != tc.err {
				t.Errorf("want error %v, got %v", tc.err, err)
			}
			if home != tc.want {
				t.Errorf("want home %q, got %q", tc.want, home)
			}
		})
	}
}
