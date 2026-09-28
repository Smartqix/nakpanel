package site

import "testing"

func TestParseSubdomainLabelAcceptsShortAndMatchingFullName(t *testing.T) {
	for _, input := range []string{"blog", "Blog.Example.Test", " blog.example.test. "} {
		got, err := ParseSubdomainLabel(input, "example.test")
		if err != nil || got != "blog" {
			t.Fatalf("ParseSubdomainLabel(%q) = %q, %v; want blog", input, got, err)
		}
	}
}

func TestParseSubdomainLabelRejectsWrongParentAndNestedName(t *testing.T) {
	for _, input := range []string{"blog.other.test", "deep.blog.example.test", "bad_name", "-blog", "blog-", ""} {
		if got, err := ParseSubdomainLabel(input, "example.test"); err == nil {
			t.Fatalf("ParseSubdomainLabel(%q) = %q; want error", input, got)
		}
	}
}
