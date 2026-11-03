package handlers

// GET /v1/catalogue — retired (PAT-2246).
//
// This route used to serve the CI-signed global app catalogue (PAT-495) that
// endpoint agents pinned installer hashes against. Patching is not coming
// back (ruling 2026-09-28; ADR-0011 is dead), so the platform no longer
// serves the catalogue. The route answers 410 Gone rather than disappearing
// into a 404, so an agent still polling it sees an explicit, permanent
// retirement. It performs no authentication and no database read: there is
// nothing behind it to protect, and a route that reads nothing cannot be
// used to probe credentials or load the database.

import (
	"net/http"
)

// catalogueRetiredBody is the complete 410 response body.
const catalogueRetiredBody = "catalogue retired\n"

// CatalogueHandler builds the public GET /v1/catalogue handler, which always
// answers 410 Gone.
func CatalogueHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(catalogueRetiredBody))
	}
}
