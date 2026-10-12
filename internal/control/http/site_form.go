package panelhttp

import (
	"errors"
	"mime"
	"net/http"
)

const maxSiteFormBytes = 64 << 10

func parseSiteForm(r *http.Request) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return err
	}
	if mediaType != "multipart/form-data" {
		return r.ParseForm()
	}
	err = r.ParseMultipartForm(maxSiteFormBytes)
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	if err != nil {
		return err
	}
	if len(r.MultipartForm.File) > 0 {
		return errors.New("site creation does not accept uploaded files")
	}
	return nil
}
