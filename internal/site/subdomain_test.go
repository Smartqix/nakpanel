package site

import "testing"

func TestValidateSubdomainLabel(t *testing.T) {
	for _, value := range []string{"blog", "shop-2", "a"} {
		if err := ValidateSubdomainLabel(value); err != nil {
			t.Fatalf("valid label %q: %v", value, err)
		}
	}
	for _, value := range []string{"", "blog.example", "*.example", "-blog", "blog-", "a_b", "xn--"} {
		if err := ValidateSubdomainLabel(value); err == nil {
			t.Fatalf("invalid label %q was accepted", value)
		}
	}
}
