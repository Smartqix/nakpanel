//go:build !linux && !darwin

package ops

import "errors"

func prepareRootlessFilesystem(string, string, applicationIdentity, []byte) error {
	return errors.New("rootless filesystem preparation requires Linux or Darwin descriptor support")
}

func writeExistingRootlessConfig(applicationIdentity, []byte) error {
	return errors.New("rootless filesystem preparation requires Linux or Darwin descriptor support")
}
