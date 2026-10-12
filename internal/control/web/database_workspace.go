package web

import "strconv"

func databaseScopedURL(path string, view WorkspaceView) string {
	if view.SupportCustomerID > 0 {
		return path + "?support_customer_id=" + strconv.FormatInt(view.SupportCustomerID, 10)
	}
	return path
}
