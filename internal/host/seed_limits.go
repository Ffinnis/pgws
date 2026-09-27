package host

import "errors"

func effectiveSeedBudget(configured int64) int64 {
	if configured == 0 {
		return 512 << 20
	}
	return configured
}

// Archive and extracted data coexist until verification. Keep staging bounded
// by an explicit host quota; workspace refquotas remain 2 GiB in this profile.
func (c Config) seedLimits() (budget, baselineQuota int64, err error) {
	budget = effectiveSeedBudget(c.SeedMaxBytes)
	if budget < 32<<20 || budget > 1536<<20 {
		return 0, 0, errors.New("seed_max_bytes must be between 32 and 1536 MiB")
	}
	baselineQuota = max(2<<30, 2*budget+(256<<20))
	projectQuota := c.ProjectQuotaBytes
	if projectQuota == 0 {
		projectQuota = 2 << 30
	}
	if projectQuota < 128<<20 || projectQuota > 1<<60 {
		return 0, 0, errors.New("invalid project allocation policy")
	}
	// Preserve existing installations where an ancestor quota deliberately
	// constrains the default small-source profile. Explicit larger seed budgets
	// must declare enough project allowance for both copies during extraction.
	if c.SeedMaxBytes != 0 && baselineQuota > projectQuota {
		return 0, 0, errors.New("project quota cannot cover seed archive, extraction and WAL headroom")
	}
	return budget, baselineQuota, nil
}
