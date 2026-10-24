package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUpdateEndpointGuards(t *testing.T) {
	s, _ := setupTestServer(t)

	rec := httptest.NewRecorder()
	s.handleUpdate(rec, httptest.NewRequest(http.MethodGet, "/api/update", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("without an updater the endpoint must not exist, got %d", rec.Code)
	}

	restarted := false
	s.SetUpdater(&Updater{Version: "v0.0.1", Exe: "/nonexistent", Restart: func() { restarted = true }})

	rec = httptest.NewRecorder()
	s.handleUpdate(rec, httptest.NewRequest(http.MethodPost, "/api/update", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a POST without the action header must be refused, got %d", rec.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/update", nil)
	req.Header.Set(updateHeader, "something else")
	rec = httptest.NewRecorder()
	s.handleUpdate(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a wrong header value must be refused, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.handleUpdate(rec, httptest.NewRequest(http.MethodDelete, "/api/update", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d", rec.Code)
	}
	if restarted {
		t.Fatal("a refused request must not restart the process")
	}
}
