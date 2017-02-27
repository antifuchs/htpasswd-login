package htpasswd_test

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestCleanup(t *testing.T) {
	t.Parallel()
	ti := &timer{at: time.Now()}
	srv, dir, ts := service(t, ti)
	defer ts.Close()
	defer os.RemoveAll(dir)

	t.Logf("T at start:   %s", ti.at)
	for i := 0; i < int(srv.CookieLifetime/time.Second)+2; i++ {
		srv.NewSession(strconv.Itoa(i), "example.com")
		ti.at = ti.at.Add(1 * time.Second)
	}
	ti.at = ti.at.Add(1 * time.Second)
	t.Logf("T at cleanup: %s", ti.at)
	srv.RunCleanup()
	existingSessions := 0
	err := filepath.Walk(srv.SessionDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if path != srv.SessionDir {
				return filepath.SkipDir
			} else {
				return nil
			}
		}
		existingSessions++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := int(srv.CookieLifetime/time.Second) - 3
	if existingSessions < expected || existingSessions == 0 {
		t.Errorf("Expected about %d sessions, got %d", expected, existingSessions)
	}
}
