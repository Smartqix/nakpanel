package quota

import (
	"bufio"
	"context"
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
)

type phpLogSecretReader interface {
	GetSecret(context.Context, string, string) ([]byte, serveradmin.SecretReference, error)
}

func (s *SQLStore) RedactPHPEnvironmentSecrets(ctx context.Context, siteID int64, lines []string) ([]string, error) {
	if s == nil || s.db == nil || siteID <= 0 {
		return nil, errors.New("PHP log secret redaction is unavailable")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT secret.scope,secret.name
FROM php_environment_bindings binding
JOIN php_applications application ON application.id=binding.application_id
JOIN service_secrets secret ON secret.id=binding.secret_id AND secret.scope=binding.secret_scope
WHERE application.site_id=$1 AND binding.secret_id IS NOT NULL
ORDER BY secret.id`, siteID)
	if err != nil {
		return nil, err
	}
	type reference struct{ scope, name string }
	var references []reference
	for rows.Next() {
		var item reference
		if err := rows.Scan(&item.scope, &item.name); err != nil {
			rows.Close()
			return nil, err
		}
		references = append(references, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(references) == 0 {
		return lines, nil
	}
	if s.phpLogSecrets == nil {
		return nil, errors.New("PHP log secret redaction is unavailable")
	}
	values := make([]string, 0, len(references))
	seen := make(map[string]struct{})
	for _, reference := range references {
		plaintext, _, err := s.phpLogSecrets.GetSecret(ctx, reference.scope, reference.name)
		if err != nil {
			return nil, err
		}
		for _, value := range phpLogSecretFragments(string(plaintext)) {
			if _, exists := seen[value]; !exists {
				seen[value] = struct{}{}
				values = append(values, value)
			}
		}
		clear(plaintext)
	}
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	for index := range lines {
		for _, value := range values {
			lines[index] = strings.ReplaceAll(lines[index], value, "[REDACTED]")
		}
	}
	return lines, nil
}

func phpLogSecretFragments(value string) []string {
	reader := bufio.NewReader(strings.NewReader(value))
	var fragments []string
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			line = strings.TrimRight(line, "\r\n")
			line = strings.Map(func(r rune) rune {
				if r == '\t' || r >= 0x20 {
					return r
				}
				return '\uFFFD'
			}, line)
			if line != "" {
				fragments = append(fragments, line)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			break
		}
	}
	return fragments
}
