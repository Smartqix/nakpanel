package ops

import "testing"

func TestGrantDatabaseQuotesLiteralPatternsWithoutChangingIdentifiers(t *testing.T) {
	for _, test := range []struct{ name, grant, identifier string }{
		{"plain", "`plain`", "`plain`"},
		{"np_demo", "`np\\_demo`", "`np_demo`"},
		{"np%demo", "`np\\%demo`", "`np%demo`"},
		{"np\\_%demo", "`np\\\\\\_\\%demo`", "`np\\_%demo`"},
		{"np`_demo", "`np``\\_demo`", "`np``_demo`"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := quoteMariaDBGrantDatabase(test.name); got != test.grant {
				t.Fatalf("grant = %q, want %q", got, test.grant)
			}
			if got := quoteMariaDBIdentifier(test.name); got != test.identifier {
				t.Fatalf("identifier = %q, want %q", got, test.identifier)
			}
		})
	}
}
