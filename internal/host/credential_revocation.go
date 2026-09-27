package host

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"pgws/internal/control"
)

func (h *Host) RevokeCredentials(ctx context.Context, t control.Task) error {
	if t.Kind != "revoke_credentials" || t.Command.Host != h.Config.ID || t.Command.Epoch != h.Config.Epoch || !control.ValidID(t.Command.Workspace) {
		return errors.New("invalid credential revocation scope")
	}
	var request []control.CredentialRevocation
	if json.Unmarshal(t.Document, &request) != nil || len(request) == 0 || len(request) > 10000 {
		return errors.New("credential identity differs")
	}
	var users []string
	for _, credential := range request {
		if !control.ValidID(credential.ID) || credential.Username != "pgws_"+strings.ReplaceAll(credential.ID, "-", "") {
			return errors.New("credential identity differs")
		}
		users = append(users, credential.Username)
	}
	unlock := h.lock(t.Command.Workspace)
	defer unlock()
	s, err := h.load(t)
	if err != nil {
		return err
	}
	want := t.Command.Identity
	want.Revision = s.Task.Command.Revision
	if s.Task.Command.Identity != want || s.GuardDirectory == "" {
		return errors.New("credential generation differs")
	}
	if s.Phase == "deleted" {
		return nil
	}
	// Revocation is permanent for this random username within its immutable
	// generation. It does not need or advance a lifecycle command fence.
	body, _ := json.Marshal(map[string][]string{"usernames": users})
	return guardRequest(ctx, s.GuardDirectory, "revoke_credentials", body, nil)
}
