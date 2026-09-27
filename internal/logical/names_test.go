package logical

import (
	"strings"
	"testing"

	"pgws/internal/control"
)

func TestBaselineObjectNamespace(t *testing.T) {
	legacy := Identity{Source: control.ID(), Epoch: 1}
	slot, publication, err := sourceObjectNames(legacy)
	if err != nil || slot != "pgws_l_"+strings.ReplaceAll(legacy.Source, "-", "")+"_1" || publication != "pgws_p_"+strings.ReplaceAll(legacy.Source, "-", "")+"_1" {
		t.Fatal("legacy identity changed", err)
	}
	named := legacy
	named.Baseline = control.ID()
	named.Generation = 1
	first, _, err := sourceObjectNames(named)
	if err != nil || len(first) > 63 {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Identity){"source": func(i *Identity) { i.Source = control.ID() }, "epoch": func(i *Identity) { i.Epoch++ }, "baseline": func(i *Identity) { i.Baseline = control.ID() }, "generation": func(i *Identity) { i.Generation++ }} {
		t.Run(name, func(t *testing.T) {
			other := named
			change(&other)
			slot, pub, err := sourceObjectNames(other)
			if err != nil || slot == first || len(slot) > 63 || len(pub) > 63 {
				t.Fatal("generation namespace collision", err)
			}
		})
	}
	invalid := named
	invalid.Generation = 0
	if _, _, err := sourceObjectNames(invalid); err == nil {
		t.Fatal("partial baseline identity accepted")
	}
	invalid = named
	invalid.Baseline = ""
	if _, _, err := sourceObjectNames(invalid); err == nil {
		t.Fatal("generation without baseline accepted")
	}
}
