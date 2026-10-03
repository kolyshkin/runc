package main

import (
	"net/http"
	"os"
)

// DO NOT MERGE: test the binary size check.
func init() {
	if os.Getenv("RUNC_BLOAT_TEST") != "" {
		_ = http.ListenAndServe(":0", nil)
	}
}
