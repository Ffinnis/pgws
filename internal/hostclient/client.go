// Package hostclient is the unprivileged control-plane side of the local host
// channel. It has no dependency on container or storage implementations.
package hostclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"

	"pgws/internal/control"
)

type Client struct{ Socket, Token string }

func (c Client) ApproveLogical(ctx context.Context, t control.Task, token string) error {
	return c.call(ctx, "approve_logical", t, token, nil)
}

func (c Client) RecoveryReport(ctx context.Context, t control.Task) (control.RecoveryReport, error) {
	var report control.RecoveryReport
	err := c.call(ctx, "recovery_report", t, "", &report)
	return report, err
}

type Request struct {
	Task  control.Task `json:"task"`
	Lease string       `json:"lease,omitempty"`
}

func (c Client) call(ctx context.Context, action string, t control.Task, lease string, out any) error {
	if !filepath.IsAbs(c.Socket) || len(c.Token) < 32 {
		return errors.New("private host channel is not configured")
	}
	body, e := json.Marshal(Request{Task: t, Lease: lease})
	if e != nil {
		return e
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", c.Socket)
	}}
	defer transport.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, "POST", "http://host/"+action, bytes.NewReader(body))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	r, e := (&http.Client{Transport: transport}).Do(req)
	if e != nil {
		return control.ErrHostUnavailable
	}
	defer r.Body.Close()
	if r.StatusCode != 200 && r.StatusCode != 204 {
		return errors.New("host rejected operation")
	}
	if out != nil {
		if json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(out) != nil {
			return control.ErrHostUnavailable
		}
	}
	return nil
}
func (c Client) Execute(ctx context.Context, t control.Task) (control.Outcome, error) {
	var out control.Outcome
	e := c.call(ctx, "execute", t, "", &out)
	return out, e
}
func (c Client) Revoke(ctx context.Context, t control.Task) error {
	return c.call(ctx, "revoke", t, "", nil)
}
func (c Client) Activate(ctx context.Context, t control.Task, lease string) error {
	return c.call(ctx, "activate", t, lease, nil)
}

func (c Client) Observe(ctx context.Context, t control.Task) (control.StopObservation, error) {
	var out control.StopObservation
	err := c.call(ctx, "observe", t, "", &out)
	return out, err
}

func (c Client) RevokeServing(ctx context.Context, t control.Task) (control.StopObservation, error) {
	var out control.StopObservation
	err := c.call(ctx, "revoke_serving", t, "", &out)
	return out, err
}

func (c Client) RevokeCredentials(ctx context.Context, t control.Task) error {
	return c.call(ctx, "revoke_credentials", t, "", nil)
}

func (c Client) CollectUsage(ctx context.Context, t control.Task) (control.CapacityBatch, error) {
	var batch control.CapacityBatch
	err := c.call(ctx, "collect_usage", t, "", &batch)
	return batch, err
}
func (c Client) AcknowledgeUsage(ctx context.Context, t control.Task) error {
	return c.call(ctx, "acknowledge_usage", t, "", nil)
}
