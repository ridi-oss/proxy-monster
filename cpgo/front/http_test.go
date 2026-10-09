package front

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHTTPPreservesHostAndNamesThePeer(t *testing.T) {
	var gotHost, gotXFF string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotXFF = r.Host, r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusTeapot)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	front := httptest.NewServer(NewHTTP(u, ParseTrustedEdges(nil)))
	defer front.Close()

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/api/x", nil)
	req.Host = "pm.example"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot || gotHost != "pm.example" || gotXFF != "127.0.0.1" {
		t.Fatalf("status %d host %q xff %q", resp.StatusCode, gotHost, gotXFF)
	}
}

func TestHTTPStreamsServerSentEvents(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
	}))
	defer upstream.Close()
	defer close(release)
	u, _ := url.Parse(upstream.URL)
	front := httptest.NewServer(NewHTTP(u, ParseTrustedEdges(nil)))
	defer front.Close()

	resp, err := http.Get(front.URL + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(resp.Body).ReadString('\n')
		line <- s
	}()
	select {
	case s := <-line:
		if !strings.HasPrefix(s, "data: first") {
			t.Fatalf("first line %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("event was buffered instead of streamed")
	}
}

func TestHTTPUpstreamDownIsBadGateway(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:1")
	front := httptest.NewServer(NewHTTP(u, ParseTrustedEdges(nil)))
	defer front.Close()
	resp, err := http.Get(front.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
