package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

func (s *Server) listUsage(ctx context.Context, tx pgx.Tx, p Principal, r *http.Request, _ []byte) (int, any, error) {
	limit := 100
	query := r.URL.Query()
	for key, values := range query {
		if (key != "limit" && key != "cursor") || len(values) != 1 || values[0] == "" {
			return 0, nil, fail(400, "INVALID_REQUEST", "Invalid pagination query")
		}
	}
	if v := query.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			return 0, nil, fail(400, "INVALID_REQUEST", "Page limit must be between 1 and 200")
		}
		limit = n
	}
	var beforeTime, beforeID any
	if cursor := query.Get("cursor"); cursor != "" {
		var parts []string
		raw, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
		if len(cursor) > 1024 || err != nil || json.Unmarshal(raw, &parts) != nil || len(parts) != 5 || parts[0] != "usage-v1" || parts[1] != p.Tenant || parts[2] != p.Project || !ValidID(parts[4]) {
			return 0, nil, fail(400, "INVALID_CURSOR", "Cursor does not belong to this usage history")
		}
		at, err := time.Parse(time.RFC3339Nano, parts[3])
		if err != nil {
			return 0, nil, fail(400, "INVALID_CURSOR", "Invalid observation cursor")
		}
		beforeTime, beforeID = at, parts[4]
	}
	rows, err := tx.Query(ctx, `SELECT id::text,resource_reference,metric,amount::text,unit,interval_start,interval_end,dimensions FROM usage_events
 WHERE tenant_id=$1 AND project_id=$2 AND ($3::timestamptz IS NULL OR (interval_end,id)<($3::timestamptz,$4::uuid)) ORDER BY interval_end DESC,id DESC LIMIT $5`, p.Tenant, p.Project, beforeTime, beforeID, limit+1)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	items := []Object{}
	for rows.Next() {
		var id, resource, metric, amount, unit string
		var start, end time.Time
		var dimensions json.RawMessage
		if err = rows.Scan(&id, &resource, &metric, &amount, &unit, &start, &end, &dimensions); err != nil {
			return 0, nil, err
		}
		items = append(items, Object{"id": id, "resource_reference": resource, "metric": metric, "amount": amount, "unit": unit, "interval_start": start, "interval_end": end, "dimensions": dimensions})
	}
	if err = rows.Err(); err != nil {
		return 0, nil, err
	}
	result := Object{"items": items, "measurement_kind": "observed_gauge"}
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		raw, _ := json.Marshal([]string{"usage-v1", p.Tenant, p.Project, last["interval_end"].(time.Time).Format(time.RFC3339Nano), last["id"].(string)})
		result["items"] = items
		result["next_cursor"] = base64.RawURLEncoding.EncodeToString(raw)
	}
	return 200, result, nil
}
