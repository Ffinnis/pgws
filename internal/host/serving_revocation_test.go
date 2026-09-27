package host

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"pgws/internal/control"
)

func testConnectedRevocation(t *testing.T, ctx context.Context, mg, client *pgx.Conn, c Config, workspace string, revoker control.ServingRevoker) {
	t.Helper()
	path := filepath.Join(c.Root, "objects", workspace, "1", "state.json")
	var s state
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &s) != nil {
		t.Fatal("revocation fixture state", err)
	}
	stale := s.Task
	stale.Kind = "revoke_serving"
	stale.Command.Token--
	if _, err = revoker.RevokeServing(ctx, stale); err == nil {
		t.Fatal("stale fence revoked serving runtime")
	}
	if _, err = client.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatal("stale revoke interrupted SQL", err)
	}
	tenant, project := s.Task.Command.Tenant, s.Task.Command.Project
	defer mg.Exec(context.Background(), "UPDATE pgws_control.api_tokens SET allow_raw=true WHERE tenant_id=$1 AND project_id=$2", tenant, project)
	started := time.Now()
	if _, err = mg.Exec(ctx, "UPDATE pgws_control.api_tokens SET allow_raw=false WHERE tenant_id=$1 AND project_id=$2", tenant, project); err != nil {
		t.Fatal(err)
	}
	for {
		query, done := context.WithTimeout(ctx, time.Second)
		_, err = client.Exec(query, "SELECT 1")
		done()
		if err != nil {
			break
		}
		if time.Since(started) > 5*time.Second {
			t.Fatal("connected revocation retained SQL beyond five seconds")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cutoff := time.Since(started)
	if cutoff > 5*time.Second {
		t.Fatal("connected revocation exceeded five seconds", cutoff)
	}
	for {
		var phase string
		if err = mg.QueryRow(ctx, "SELECT phase FROM pgws_control.workspaces WHERE id=$1", workspace).Scan(&phase); err != nil {
			t.Fatal(err)
		}
		if phase == "failed" {
			break
		}
		if time.Since(started) > 6*time.Second {
			t.Fatal("connected revocation did not reach management")
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop, err := readStop(filepath.Dir(path))
	if err != nil || stop.Reason != "AUTHORIZATION_REVOKED" {
		t.Fatal("revocation durable stop", stop.Reason, err)
	}
	if _, err = os.Stat(s.Recovery.DataDir); err != nil {
		t.Fatal("revocation destroyed retained writes", err)
	}
	var live int
	if err = mg.QueryRow(ctx, "SELECT count(*) FROM pgws_control.credentials WHERE workspace_id=$1 AND revoked_at IS NULL", workspace).Scan(&live); err != nil || live != 0 {
		t.Fatal("revocation retained credentials", live, err)
	}
	t.Logf("Connected raw-grant revocation closed actual SQL in %s, retained storage, revoked credentials and rejected a stale host fence", cutoff)
}

func testPrincipalRevocation(t *testing.T, ctx context.Context, mg, other *pgx.Conn, address, tenant, project, workspace, cert string) {
	t.Helper()
	principal := control.ID()
	token := control.ID() + control.ID()
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	if _, err := mg.Exec(ctx, `INSERT INTO pgws_control.api_tokens(token_hash,principal_id,tenant_id,project_id,allow_raw,expires_at) VALUES($1,$2,$3,$4,true,now()+interval '1 hour')`, hash, principal, tenant, project); err != nil {
		t.Fatal(err)
	}
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(requestCtx, "POST", "http://"+address+"/v1/projects/"+project+"/workspaces/"+workspace+"/credentials", strings.NewReader(`{"expected_generation":1,"role":"reader","ttl_seconds":60}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "principal-revocation")
	response, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal("principal credential request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 201 {
		t.Fatal("principal credential request status", response.StatusCode)
	}
	var credential struct {
		ID, Username, Password string
		Endpoint               struct {
			Hostname, Database string
			Port               int
		}
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&credential); err != nil {
		t.Fatal("principal credential response invalid")
	}
	u := url.URL{Scheme: "postgresql", Host: net.JoinHostPort(credential.Endpoint.Hostname, fmt.Sprint(credential.Endpoint.Port)), Path: "/" + credential.Endpoint.Database, User: url.UserPassword(credential.Username, credential.Password)}
	u.RawQuery = url.Values{"sslmode": {"verify-full"}, "sslrootcert": {cert}}.Encode()
	client, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal("principal SQL connection failed")
	}
	defer client.Close(context.Background())
	if _, err = client.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err = mg.Exec(ctx, "UPDATE pgws_control.api_tokens SET revoked_at=clock_timestamp() WHERE token_hash=$1", hash); err != nil {
		t.Fatal(err)
	}
	for {
		query, done := context.WithTimeout(ctx, time.Second)
		_, err = client.Exec(query, "SELECT 1")
		done()
		if err != nil {
			break
		}
		if time.Since(started) > 5*time.Second {
			t.Fatal("principal revocation did not close its SQL session")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cutoff := time.Since(started)
	if cutoff > 5*time.Second {
		t.Fatal("principal cutoff exceeded five seconds", cutoff)
	}
	if _, err = other.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatal("principal revocation interrupted another user's SQL", err)
	}
	for {
		var delivered bool
		if err = mg.QueryRow(ctx, "SELECT revoked_at IS NOT NULL AND host_revoked_at IS NOT NULL FROM pgws_control.credentials WHERE id=$1", credential.ID).Scan(&delivered); err != nil {
			t.Fatal(err)
		}
		if delivered {
			break
		}
		if time.Since(started) > 6*time.Second {
			t.Fatal("principal revocation delivery was not acknowledged")
		}
		time.Sleep(20 * time.Millisecond)
	}
	check, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	if connection, e := pgx.Connect(check, u.String()); e == nil {
		connection.Close(check)
		t.Fatal("revoked credential reconnected")
	}
	t.Logf("Principal token revocation closed only its SQL session in %s; another user stayed connected and revoked credentials could not reconnect", cutoff)
}
