//go:build linux

package classify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"pgws/internal/privacy/features"
)

// Run only in a fresh, CPU-pinned container. A child process starts without the
// fixture builder's allocations so the model's RSS increase is not hidden by
// already committed pages in a warm Go heap. Arithmetic weights exercise the
// exact full matrix shape and scoring loops, not trained-model accuracy.
func TestClassifierResources(t *testing.T) {
	if os.Getenv("PGWS_CLASSIFIER_RESOURCE_LAB") != "1" {
		t.Skip("requires isolated CPU-pinned resource lab")
	}
	if os.Getenv("PGWS_CLASSIFIER_RESOURCE_CHILD") != "1" {
		data, _ := fixtureBundle(nil)
		path := filepath.Join(t.TempDir(), "fixture.model")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(os.Args[0], "-test.run=^TestClassifierResources$", "-test.v", "-test.timeout=90s")
		command.Env = append(os.Environ(), "PGWS_CLASSIFIER_RESOURCE_CHILD=1", "PGWS_CLASSIFIER_FIXTURE="+path)
		output, err := command.CombinedOutput()
		fmt.Print(string(output))
		if err != nil {
			t.Fatal("isolated classifier resource run failed", err)
		}
		return
	}
	runtime.GOMAXPROCS(1)
	profiles := resourceProfiles(t)
	debug.FreeOSMemory()
	baseline, _ := residentBytes(t)
	file, err := os.Open(os.Getenv("PGWS_CLASSIFIER_FIXTURE"))
	if err != nil {
		t.Fatal(err)
	}
	// The fixed public key is for this arithmetic fixture only.
	_, key := fixturePublicKey()
	model, err := Load(file, key)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	latencies := []map[string]any{}
	for index, profile := range profiles {
		for i := 0; i < 50; i++ {
			v, e := features.Extract(profile)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = model.Score(context.Background(), v); e != nil {
				t.Fatal(e)
			}
		}
		elapsed := make([]int64, 1000)
		var entries int
		for i := range elapsed {
			start := time.Now()
			v, e := features.Extract(profile)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = model.Score(context.Background(), v); e != nil {
				t.Fatal(e)
			}
			elapsed[i] = time.Since(start).Nanoseconds()
			entries = len(v.Entries)
		}
		slices.Sort(elapsed)
		p95 := float64(elapsed[949]) / 1e6
		latencies = append(latencies, map[string]any{"fixture": index, "entries": entries, "iterations": len(elapsed), "p50_ms": float64(elapsed[499]) / 1e6, "p95_ms": p95})
		if p95 >= 5 {
			t.Errorf("profile %d extraction+score p95 %.3fms exceeds 5ms", index, p95)
		}
	}
	var group sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			for j := 0; j < 100; j++ {
				v, e := features.Extract(profiles[2])
				if e != nil {
					t.Error(e)
					return
				}
				if _, e = model.Score(context.Background(), v); e != nil {
					t.Error(e)
					return
				}
			}
		}()
	}
	close(start)
	group.Wait()
	rss, peak := residentBytes(t)
	increase := max(int64(0), peak-baseline)
	if increase > 32<<20 {
		t.Errorf("resident increase %d exceeds 32 MiB", increase)
	}
	info, _ := os.ReadFile("/proc/cpuinfo")
	cpu := []string{}
	for _, line := range strings.Split(string(info), "\n") {
		if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "CPU implementer") || strings.HasPrefix(line, "CPU part") {
			if !slices.Contains(cpu, line) {
				cpu = append(cpu, line)
			}
		}
	}
	status, _ := os.ReadFile("/proc/self/status")
	var allowed string
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Cpus_allowed_list:") {
			allowed = strings.TrimSpace(strings.TrimPrefix(line, "Cpus_allowed_list:"))
		}
	}
	report := map[string]any{"status": "passed", "architecture": runtime.GOARCH, "go": runtime.Version(), "gomaxprocs": 1, "cpus_allowed": allowed, "cpu": cpu, "profile_latency": latencies, "baseline_rss_bytes": baseline, "final_rss_bytes": rss, "peak_rss_bytes": peak, "resident_increase_bytes": increase, "concurrent_inferences": 8, "bundle_bytes": int64(0), "weights": "project-authored arithmetic fixture; no trained-model quality claim", "feature_contract_digest": features.ContractDigest()}
	if stat, e := os.Stat(os.Getenv("PGWS_CLASSIFIER_FIXTURE")); e == nil {
		report["bundle_bytes"] = stat.Size()
	}
	if t.Failed() {
		report["status"] = "failed"
	}
	encoded, _ := json.Marshal(report)
	fmt.Println("CLASSIFIER_RESOURCES=" + string(encoded))
	runtime.KeepAlive(model)
}

func residentBytes(t *testing.T) (int64, int64) {
	t.Helper()
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	var rss, peak int64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && (fields[0] == "VmRSS:" || fields[0] == "VmHWM:") {
			n, e := strconv.ParseInt(fields[1], 10, 64)
			if e != nil {
				t.Fatal(e)
			}
			if fields[0] == "VmRSS:" {
				rss = n * 1024
			} else {
				peak = n * 1024
			}
		}
	}
	if rss == 0 || peak == 0 {
		t.Fatal("RSS accounting unavailable")
	}
	return rss, peak
}

func resourceProfiles(t *testing.T) []features.Profile {
	t.Helper()
	email := "fixture@example.org"
	sample := make([]features.Sample, 64)
	for i := range sample {
		sample[i] = features.Sample{Value: &email}
	}
	ordinary, err := features.ProfileSamples(features.Metadata{Table: "people", Column: "emailAddress", Type: "varchar", Neighbors: []string{"id", "fullName", "createdAt"}}, sample, true)
	if err != nil {
		t.Fatal(err)
	}
	missing, err := features.ProfileSamples(features.Metadata{Table: "events", Column: "payload", Type: "jsonb"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	neighbors := []string{}
	for i := 0; i < 32; i++ {
		h := sha256.Sum256([]byte(strconv.Itoa(i)))
		neighbors = append(neighbors, hex.EncodeToString(h[:])+hex.EncodeToString(h[:]))
	}
	stress, err := features.ProfileSamples(features.Metadata{Table: strings.Repeat("long_table_", 20), Column: strings.Repeat("long_column_", 20), Type: "varchar", Neighbors: neighbors}, sample, true)
	if err != nil {
		t.Fatal(err)
	}
	return []features.Profile{ordinary, missing, stress}
}

// Unlike fixtureBundle, this allocates only the Ed25519 key, not 1.5 MiB of
// fixture weights inside the process being measured.
func fixturePublicKey() ([]byte, []byte) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32))
	return key, key.Public().(ed25519.PublicKey)
}
