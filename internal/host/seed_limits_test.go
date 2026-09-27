package host

import "testing"

func TestSeedLimits(t *testing.T) {
	budget, quota, err := (Config{}).seedLimits()
	if err != nil || budget != 512<<20 || quota != 2<<30 {
		t.Fatal(budget, quota, err)
	}
	budget, quota, err = (Config{SeedMaxBytes: 1536 << 20, ProjectQuotaBytes: 4 << 30}).seedLimits()
	if err != nil || budget != 1536<<20 || quota != 3328<<20 {
		t.Fatal(budget, quota, err)
	}
	for _, c := range []Config{{SeedMaxBytes: -1}, {SeedMaxBytes: 31 << 20}, {SeedMaxBytes: 1537 << 20}, {SeedMaxBytes: 1536 << 20}, {ProjectQuotaBytes: -1}} {
		if _, _, err := c.seedLimits(); err == nil {
			t.Fatal("invalid staging budget accepted", c)
		}
	}
	if effectiveSeedBudget(0) != 512<<20 {
		t.Fatal("legacy generation budget changed")
	}
	if _, _, err := (Config{ProjectQuotaBytes: 128 << 20}).seedLimits(); err != nil {
		t.Fatal("legacy small project admission changed", err)
	}
}
