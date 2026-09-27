package host

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"pgws/internal/control"
	"pgws/internal/physical"
	"pgws/internal/secrets"
)

func (h *Host) issueCredential(ctx context.Context, t control.Task) (control.Outcome, error) {
	s, err := h.load(t)
	if err != nil {
		return control.Outcome{}, err
	}
	var request control.CredentialRequest
	if json.Unmarshal(t.Document, &request) != nil || s.Phase != "ready" || request.Expiry.After(t.Expiry) || !request.Expiry.After(time.Now()) || s.Task.Command.Tenant != t.Command.Tenant || s.Task.Command.Project != t.Command.Project {
		return control.Outcome{}, errors.New("credential request is not current")
	}
	key, err := base64.StdEncoding.DecodeString(h.Config.SecretKey)
	if err != nil || len(key) != 32 {
		return control.Outcome{}, errors.New("host credential encryption key unavailable")
	}
	path := filepath.Join(h.folder(t), "credential-plans", t.Command.Operation+".json")
	var plan struct {
		Credential physical.Credential `json:"credential"`
		Role       string              `json:"role"`
	}
	var stored struct {
		Sealed string `json:"sealed"`
	}
	b, err := os.ReadFile(path)
	if err == nil {
		if json.Unmarshal(b, &stored) != nil {
			return control.Outcome{}, errors.New("invalid credential plan")
		}
		plain, e := secrets.Open(key, stored.Sealed, control.CredentialAAD(t))
		if e != nil || json.Unmarshal(plain, &plan) != nil {
			return control.Outcome{}, errors.New("credential plan authentication failed")
		}
		if plan.Role != request.Role || !plan.Credential.ExpiresAt.Equal(request.Expiry) {
			return control.Outcome{}, errors.New("credential plan differs from request")
		}
	} else if os.IsNotExist(err) {
		plan.Role = request.Role
		plan.Credential, err = physical.NewCredential(request.Expiry)
		if err != nil {
			return control.Outcome{}, err
		}
		plain, _ := json.Marshal(plan)
		stored.Sealed, err = secrets.Seal(key, plain, control.CredentialAAD(t))
		if err != nil {
			return control.Outcome{}, err
		}
		if err = save(path, stored); err != nil {
			return control.Outcome{}, err
		}
	} else {
		return control.Outcome{}, err
	}
	if err = physical.InstallCredential(ctx, s.Recovery, s.Access, plan.Role, plan.Credential); err != nil {
		return control.Outcome{}, err
	}
	var status guardStatus
	if err = guardRequest(ctx, s.GuardDirectory, "status", nil, &status); err != nil {
		return control.Outcome{}, err
	}
	host, port, err := net.SplitHostPort(status.Address)
	if err != nil {
		return control.Outcome{}, err
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return control.Outcome{}, err
	}
	credential := plan.Credential
	registration, _ := json.Marshal(map[string]any{"username": credential.Username, "expires_at": credential.ExpiresAt})
	if err = guardRequest(ctx, s.GuardDirectory, "credential", registration, nil); err != nil {
		return control.Outcome{}, err
	}
	response, _ := json.Marshal(map[string]any{"id": credential.ID, "workspace_id": t.Command.Workspace, "generation": t.Command.Generation, "username": credential.Username, "password": credential.Password, "expires_at": credential.ExpiresAt, "endpoint": map[string]any{"hostname": host, "port": n, "database": s.Access.Databases[0], "sslmode": "verify-full"}})
	sealed, err := secrets.Seal(key, response, control.CredentialAAD(t))
	if err != nil {
		return control.Outcome{}, err
	}
	out := control.Outcome{Phase: "ready", Credential: &control.CredentialOutcome{ID: credential.ID, Username: credential.Username, Expiry: credential.ExpiresAt, Sealed: sealed}}
	s.Task = t
	s.Outcome = out
	if err = h.save(t, s); err != nil {
		return out, err
	}
	return out, nil
}
