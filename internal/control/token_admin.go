package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Token administration uses an operator database login. Runtime and worker
// roles cannot insert or update API grants. Plaintext is returned once only.
type TokenGrant struct {
	ID        string     `json:"id"`
	Principal string     `json:"principal_id"`
	Tenant    string     `json:"tenant_id"`
	Project   string     `json:"project_id"`
	Admin     bool       `json:"is_admin"`
	Raw       bool       `json:"allow_raw"`
	Expiry    time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

func tokenAuthority(ctx context.Context, tx pgx.Tx, epoch string, issue bool) error {
	if !ValidID(epoch) {
		return errors.New("explicit authority epoch required")
	}
	if _, err := tx.Exec(ctx, "SET LOCAL search_path=pg_catalog,pgws_control; SET LOCAL synchronous_commit=on"); err != nil {
		return errors.New("token transaction settings unavailable")
	}
	var current bool
	var reconciled bool
	if err := tx.QueryRow(ctx, `SELECT epoch=$1::uuid,reconciled FROM pgws_control.authority WHERE singleton FOR SHARE`, epoch).Scan(&current, &reconciled); err != nil {
		return errors.New("token authority unavailable")
	}
	if !current || issue && !reconciled {
		return errors.New("token authority changed or issuance is fenced")
	}
	return nil
}

func CreateAPIToken(ctx context.Context, pool *pgxpool.Pool, epoch string, grant TokenGrant, ttl time.Duration, replace string) (TokenGrant, string, error) {
	var empty TokenGrant
	if !ValidID(grant.Tenant) || !ValidID(grant.Project) || ttl < 5*time.Minute || ttl > 24*time.Hour || replace != "" && !ValidID(replace) {
		return empty, "", errors.New("valid token scope and a TTL from five minutes to 24 hours required")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return empty, "", errors.New("token transaction unavailable")
	}
	defer tx.Rollback(ctx)
	if err = tokenAuthority(ctx, tx, epoch, true); err != nil {
		return empty, "", err
	}
	if replace != "" {
		err = tx.QueryRow(ctx, `SELECT principal_id::text,is_admin,allow_raw FROM pgws_control.api_tokens WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE`, grant.Tenant, grant.Project, replace).Scan(&grant.Principal, &grant.Admin, &grant.Raw)
		if err != nil {
			return empty, "", errors.New("current token not found in the requested scope")
		}
	} else if grant.Principal == "" {
		grant.Principal = ID()
	}
	if !ValidID(grant.Principal) {
		return empty, "", errors.New("valid principal required")
	}
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		return empty, "", err
	}
	plaintext := hex.EncodeToString(secret[:])
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(plaintext)))
	grant.ID = ID()
	grant.RevokedAt = nil
	err = tx.QueryRow(ctx, `INSERT INTO pgws_control.api_tokens(id,token_hash,principal_id,tenant_id,project_id,is_admin,allow_raw,expires_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp()+make_interval(secs=>$8)) RETURNING expires_at`, grant.ID, hash, grant.Principal, grant.Tenant, grant.Project, grant.Admin, grant.Raw, ttl.Seconds()).Scan(&grant.Expiry)
	if err != nil {
		return empty, "", errors.New("token creation failed; verify project scope and operator privileges")
	}
	action := "token.create"
	if replace != "" {
		action = "token.rotate"
		if _, err = tx.Exec(ctx, `UPDATE pgws_control.api_tokens SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, grant.Tenant, grant.Project, replace); err != nil {
			return empty, "", errors.New("token rotation failed")
		}
	}
	metadata, _ := json.Marshal(Object{"grant": grant, "replaced_token_id": replace})
	if _, err = tx.Exec(ctx, `INSERT INTO pgws_control.audit_events(id,tenant_id,project_id,actor_reference,action,target_reference,outcome,safe_metadata) VALUES($1,$2,$3,'operator:'||current_user::text,$4,$5,'succeeded',$6)`, ID(), grant.Tenant, grant.Project, action, grant.ID, metadata); err != nil {
		return empty, "", errors.New("token audit failed")
	}
	if err = tx.Commit(ctx); err != nil {
		return empty, "", errors.New("token commit acknowledgement unavailable; inspect token metadata before retrying")
	}
	return grant, plaintext, nil
}

func ListAPITokens(ctx context.Context, pool *pgxpool.Pool, tenant, project, after string, limit int) ([]TokenGrant, error) {
	if !ValidID(tenant) || !ValidID(project) || after != "" && !ValidID(after) || limit < 1 || limit > 1000 {
		return nil, errors.New("valid token scope, cursor and limit required")
	}
	rows, err := pool.Query(ctx, `SELECT id::text,principal_id::text,tenant_id::text,project_id::text,is_admin,allow_raw,expires_at,revoked_at FROM pgws_control.api_tokens WHERE tenant_id=$1 AND project_id=$2 AND ($3::uuid IS NULL OR id>$3::uuid) ORDER BY id LIMIT $4`, tenant, project, nullableTokenCursor(after), limit)
	if err != nil {
		return nil, errors.New("token inventory unavailable")
	}
	defer rows.Close()
	result := []TokenGrant{}
	for rows.Next() {
		var g TokenGrant
		if err = rows.Scan(&g.ID, &g.Principal, &g.Tenant, &g.Project, &g.Admin, &g.Raw, &g.Expiry, &g.RevokedAt); err != nil {
			return nil, err
		}
		result = append(result, g)
	}
	return result, rows.Err()
}

func nullableTokenCursor(cursor string) any {
	if cursor == "" {
		return nil
	}
	return cursor
}

func RevokeAPITokens(ctx context.Context, pool *pgxpool.Pool, epoch, tenant, project, id, principal string) (int64, error) {
	if !ValidID(tenant) || !ValidID(project) || (id == "") == (principal == "") || id != "" && !ValidID(id) || principal != "" && !ValidID(principal) {
		return 0, errors.New("valid scope and exactly one token or principal identity required")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, errors.New("token transaction unavailable")
	}
	defer tx.Rollback(ctx)
	if err = tokenAuthority(ctx, tx, epoch, false); err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, `UPDATE pgws_control.api_tokens SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND project_id=$2 AND (id=$3::uuid OR principal_id=$4::uuid) AND revoked_at IS NULL RETURNING id::text`, tenant, project, nullableTokenCursor(id), nullableTokenCursor(principal))
	if err != nil {
		return 0, errors.New("token revocation failed; verify operator privileges")
	}
	var ids []string
	for rows.Next() {
		var value string
		if err = rows.Scan(&value); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, value)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	if len(ids) > 0 {
		metadata, _ := json.Marshal(Object{"token_ids": ids, "principal_id": principal})
		target := id
		if target == "" {
			target = principal
		}
		if _, err = tx.Exec(ctx, `INSERT INTO pgws_control.audit_events(id,tenant_id,project_id,actor_reference,action,target_reference,outcome,safe_metadata) VALUES($1,$2,$3,'operator:'||current_user::text,'token.revoke',$4,'succeeded',$5)`, ID(), tenant, project, target, metadata); err != nil {
			return 0, errors.New("token revocation audit failed")
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, errors.New("token revocation commit acknowledgement unavailable; repeating revocation is safe")
	}
	return int64(len(ids)), nil
}
