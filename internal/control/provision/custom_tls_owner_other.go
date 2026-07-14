//go:build !unix

package provision

func setStagingFileOwner(_, _ string) error { return nil }
