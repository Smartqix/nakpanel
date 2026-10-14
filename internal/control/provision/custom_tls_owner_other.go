//go:build !unix

package provision

import "os"

func setStagingFileOwner(_, _ string) error { return nil }

func stagingOwnedByCurrentUser(os.FileInfo) bool { return false }
