// Package links handles reading share links from xrays.txt and summarizing them.
package links

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Read returns non-empty, non-comment lines from the given file.
func Read(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}

// Summarize returns a short human-readable description of a share link.
func Summarize(link string) string {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return link
	}
	tag := u.Fragment
	if tag == "" {
		tag = u.Host
	}
	return fmt.Sprintf("%s://%s (%s)", u.Scheme, u.Host, tag)
}

