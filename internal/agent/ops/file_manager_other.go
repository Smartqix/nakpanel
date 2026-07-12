//go:build !linux

package ops

func verifyManagedPath(root, target string) error {
	return ensureWithinRoot(root, target)
}
