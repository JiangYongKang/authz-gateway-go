package httpserver

import (
	"net/http"
	"strconv"
)

func parseInt64(w http.ResponseWriter, v string, out *int64) bool {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request", "after_id must be integer"))
		return false
	}
	*out = n
	return true
}
