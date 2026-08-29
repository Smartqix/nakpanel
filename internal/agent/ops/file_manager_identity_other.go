//go:build !linux

package ops

func assumeFileSystemIdentity(siteIdentity) (func(), error) {
	return func() {}, nil
}
