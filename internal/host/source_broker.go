package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"pgws/internal/control"
	"pgws/internal/physical"
	"pgws/internal/sourcebroker"
)

func brokerRequest(ctx context.Context, socket, action string, result any) error {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	method := "POST"
	if action == "status" {
		method = "GET"
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://source-broker/"+action, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Do(request)
	if err != nil {
		return errors.New("source broker is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 && response.StatusCode != 204 {
		return errors.New("source broker rejected control request")
	}
	if result != nil {
		return json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(result)
	}
	return nil
}

func (h *Host) ensureSourceBroker(ctx context.Context, task control.Task, source physical.Source) (string, error) {
	if err := checkStopped(h.folder(task)); err != nil {
		return "", err
	}
	if !filepath.IsAbs(h.Config.SourceBrokerBinary) {
		return "", errors.New("TCP sources require a configured source broker executable")
	}
	directory := filepath.Join(h.folder(task), "source-broker")
	socketName := "b-" + task.SourceID
	if task.Command.Generation > 1 {
		socketName += fmt.Sprintf("-%x", task.Command.Generation)
	}
	socketDir := filepath.Join(h.Config.Sockets, socketName)
	for _, path := range []string{directory, socketDir} {
		if err := os.MkdirAll(path, 0700); err != nil {
			return "", err
		}
	}
	if err := os.Chown(socketDir, 999, 999); err != nil {
		return "", err
	}
	plan := sourcebroker.ProcessConfig{Identity: task.Command.Identity, Broker: sourcebroker.Config{Endpoint: source.TLSEndpoint(), Username: source.User}, Socket: filepath.Join(socketDir, ".s.PGSQL.5432"), Control: filepath.Join(directory, "control.sock")}
	if err := plan.Broker.Validate(); err != nil {
		return "", err
	}
	configPath := filepath.Join(directory, "config.json")
	if data, err := os.ReadFile(configPath); err == nil {
		var existing sourcebroker.ProcessConfig
		if json.Unmarshal(data, &existing) != nil || !reflect.DeepEqual(existing, plan) {
			return "", errors.New("source broker differs from its reserved generation")
		}
	} else if os.IsNotExist(err) {
		if err = save(configPath, plan); err != nil {
			return "", err
		}
	} else {
		return "", err
	}
	var status sourcebroker.ProcessStatus
	if brokerRequest(ctx, plan.Control, "status", &status) != nil {
		process := exec.Command(h.Config.SourceBrokerBinary, "source-broker", configPath)
		process.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
		process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := process.Start(); err != nil {
			return "", err
		}
		go func() { _ = process.Wait() }()
	}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		if brokerRequest(wait, plan.Control, "status", &status) == nil {
			if !reflect.DeepEqual(status.Config, plan) {
				return "", errors.New("active source broker has a different generation")
			}
			if err := checkStopped(h.folder(task)); err != nil {
				_ = stopSourceBroker(ctx, h.folder(task))
				return "", err
			}
			return socketDir, nil
		}
		select {
		case <-wait.Done():
			return "", errors.New("source broker did not start")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func stopSourceBroker(ctx context.Context, folder string) error {
	path := filepath.Join(folder, "source-broker", "config.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var expected sourcebroker.ProcessConfig
	var actual sourcebroker.ProcessStatus
	if json.Unmarshal(data, &expected) != nil || expected.Control != filepath.Join(folder, "source-broker", "control.sock") {
		return errors.New("invalid source broker cleanup plan")
	}
	if err = brokerRequest(ctx, expected.Control, "status", &actual); err != nil {
		// An absent/refused control socket means the root process exited. An
		// uncertain socket or transport failure does not prove termination.
		conn, dialErr := net.DialTimeout("unix", expected.Control, 200*time.Millisecond)
		if conn != nil {
			conn.Close()
		}
		if errors.Is(dialErr, syscall.ECONNREFUSED) || errors.Is(dialErr, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !reflect.DeepEqual(expected, actual.Config) {
		return errors.New("source broker cleanup identity differs")
	}
	_ = brokerRequest(ctx, expected.Control, "shutdown", nil)
	wait, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for {
		conn, err := net.DialTimeout("unix", expected.Control, 100*time.Millisecond)
		if conn != nil {
			conn.Close()
		}
		if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		select {
		case <-wait.Done():
			return errors.New("source broker shutdown is unconfirmed")
		case <-time.After(20 * time.Millisecond):
		}
	}
}
