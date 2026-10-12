package quota

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
)

// Task runs form a byte-addressed log so the log API retains its ordinary cursor contract.
const scheduledTaskLogSQL = `WITH entries AS (
 SELECT run.id,run.finished_at,concat('Task ',run.task_id,' run ',run.id,' [',run.status,']',E'\n',run.output,E'\n') AS body
 FROM scheduled_task_runs run JOIN scheduled_tasks task ON task.id=run.task_id
 JOIN sites site ON site.id=task.site_id AND site.subscription_id=task.subscription_id
 WHERE site.id=$1 AND run.status IN ('succeeded','failed','timed_out') AND run.finished_at IS NOT NULL
), positioned AS (
 SELECT id,finished_at,body,octet_length(body)::bigint AS size_bytes,
 COALESCE(sum(octet_length(body)) OVER (ORDER BY finished_at,id ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING),0)::bigint AS start_byte
 FROM entries
), totals AS (
 SELECT COALESCE(max(start_byte+size_bytes),0)::bigint AS total_bytes FROM positioned
), bounds AS (
 SELECT total_bytes,CASE WHEN $2::bigint>total_bytes THEN 0 ELSE $2::bigint END AS cursor FROM totals
)
SELECT bounds.total_bytes,bounds.cursor,
 substring(convert_to(positioned.body,'UTF8')
 FROM (greatest(bounds.cursor,positioned.start_byte)-positioned.start_byte+1)::int
 FOR (least(positioned.start_byte+positioned.size_bytes,bounds.cursor+$3::bigint)-greatest(bounds.cursor,positioned.start_byte))::int)
FROM bounds LEFT JOIN positioned
 ON positioned.start_byte+positioned.size_bytes>bounds.cursor AND positioned.start_byte<bounds.cursor+$3::bigint
ORDER BY positioned.finished_at,positioned.id`

func (s *SQLStore) ReadScheduledTaskLog(ctx context.Context, siteID int64, req types.SiteLogRequest) (types.SiteLogResult, error) {
	if req.LineLimit == 0 {
		req.LineLimit = 200
	}
	if req.ByteLimit == 0 {
		req.ByteLimit = 256 << 10
	}
	if siteID <= 0 || req.Source != types.SiteLogTask || req.Cursor < 0 || req.LineLimit < 1 || req.LineLimit > 1000 || req.ByteLimit < 1024 || req.ByteLimit > 1<<20 {
		return types.SiteLogResult{}, errors.New("log bounds are invalid")
	}
	rows, err := s.db.QueryContext(ctx, scheduledTaskLogSQL, siteID, req.Cursor, req.ByteLimit)
	if err != nil {
		return types.SiteLogResult{}, err
	}
	defer rows.Close()
	result := types.SiteLogResult{Source: types.SiteLogTask, Lines: []string{}}
	var data bytes.Buffer
	var totalBytes int64
	for rows.Next() {
		var cursor int64
		var chunk []byte
		if err := rows.Scan(&totalBytes, &cursor, &chunk); err != nil {
			return result, err
		}
		result.NextCursor = cursor
		result.Rotated = req.Cursor > totalBytes
		if remaining := req.ByteLimit - data.Len(); len(chunk) > remaining {
			chunk = chunk[:remaining]
		}
		data.Write(chunk)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	reader := bufio.NewReader(&data)
	search, severity := strings.ToLower(req.Search), strings.ToLower(req.Severity)
	for len(result.Lines) < req.LineLimit {
		line, err := reader.ReadString('\n')
		result.NextCursor += int64(len(line))
		if line != "" {
			line = strings.Map(func(r rune) rune {
				if r == '\t' || r >= 0x20 {
					return r
				}
				return '\uFFFD'
			}, strings.TrimRight(line, "\r\n"))
			lower := strings.ToLower(line)
			if (search == "" || strings.Contains(lower, search)) && (severity == "" || strings.Contains(lower, severity)) {
				result.Lines = append(result.Lines, line)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return result, err
		}
	}
	result.Truncated = result.NextCursor < totalBytes
	return result, nil
}
