package links

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p
}

func TestRead_FiltersBlankAndComments(t *testing.T) {
	content := strings.Join([]string{
		"  ",
		"# a comment",
		"trojan://pw@host:443",
		"",
		"   vless://uuid@host:443  ",
		"#trailing comment",
	}, "\n")
	p := writeTemp(t, "links.txt", content)

	got, err := Read(p)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	want := []string{"trojan://pw@host:443", "vless://uuid@host:443"}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRead_MissingFile(t *testing.T) {
	_, err := Read(filepath.Join(t.TempDir(), "nope.txt"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestRead_EmptyFile(t *testing.T) {
	p := writeTemp(t, "empty.txt", "")
	got, err := Read(p)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 lines, got %d: %v", len(got), got)
	}
}

func TestSummarize_WithFragment(t *testing.T) {
	link := "trojan://pw@example.com:443?type=ws#My%20Server"
	got := Summarize(link)
	// Fragment should be url-decoded by net/url and shown.
	if !strings.Contains(got, "trojan://example.com:443") {
		t.Errorf("missing scheme/host in %q", got)
	}
	if !strings.Contains(got, "My Server") {
		t.Errorf("expected fragment 'My Server' in %q", got)
	}
}

func TestSummarize_WithoutFragment_FallsBackToHost(t *testing.T) {
	link := "vless://uuid@server.example:8443"
	got := Summarize(link)
	if !strings.Contains(got, "server.example:8443") {
		t.Errorf("expected host:port in summary %q", got)
	}
}

func TestSummarize_Malformed_ReturnsRaw(t *testing.T) {
	// A genuinely unparseable URL: control char in host.
	link := "://bad\x00stuff"
	got := Summarize(link)
	if got != link {
		t.Errorf("expected raw passthrough for malformed link, got %q", got)
	}
}
