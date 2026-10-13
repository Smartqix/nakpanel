package web

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestDatabasePasswordToolsDoNotCreateSecondDialogFooter(t *testing.T) {
	var output bytes.Buffer
	if err := databasePasswordInput().Render(context.Background(), &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), `class="np-dialog-actions"`) {
		t.Fatal("password tools must not become a sticky primary action footer")
	}
	for _, label := range []string{"Show password", "Copy password", "Generate password"} {
		if !strings.Contains(output.String(), label) {
			t.Errorf("missing password control %s", label)
		}
	}
}

func TestTemplateIconsExistInBundledSprite(t *testing.T) {
	f, err := os.Open("static/icons.svg")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ids := map[string]bool{}
	decoder := xml.NewDecoder(f)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if element, ok := token.(xml.StartElement); ok && element.Name.Local == "symbol" {
			for _, attr := range element.Attr {
				if attr.Name.Local == "id" {
					ids[attr.Value] = true
				}
			}
		}
	}
	references := regexp.MustCompile(`@icon\("([a-z0-9-]+)"\)`)
	files, err := filepath.Glob("*.templ")
	if err != nil {
		t.Fatal(err)
	}
	missing := map[string]bool{}
	for _, file := range files {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range references.FindAllSubmatch(source, -1) {
			name := string(match[1])
			if !ids[name] {
				missing[name] = true
			}
		}
	}
	for name := range missing {
		t.Errorf("template icon %s is missing from the embedded SVG sprite", strings.TrimSpace(name))
	}
}
