package htpasswd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// RunCleanup traverses the service's session directory and deletes
// expired sessions.
func (srv *Service) RunCleanup() {
	deleted := 0
	now := srv.Now()
	err := filepath.Walk(srv.SessionDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if path != srv.SessionDir {
				return filepath.SkipDir
			}
			return nil
		}
		name, err := filepath.Rel(srv.SessionDir, path)
		if err != nil {
			return err
		}

		sess, err := srv.unvalidatedSessionFromStorage(name)
		if err != nil {
			fmt.Printf("Session %q invalid (%s), leaving it", path, err)
			return nil
		}

		if sess.ExpiredAt(now, srv.CookieLifetime) {
			deleted++
			return os.Remove(path)
		}
		return nil
	})
	if err != nil {
		log.Printf("Couldn't delete sessions: %s", err)
		os.Exit(2)
	}
	if deleted > 0 {
		log.Printf("Cleaned out %d sessions from %q.", deleted, srv.SessionDir)
	}
}
