package logical

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"pgws/internal/control"
)

func validBaselineIdentity(i Identity) bool {
	return i.Baseline == "" && i.Generation == 0 || control.ValidID(i.Baseline) && i.Generation > 0
}

// A source may feed several immutable privacy baselines at the same source
// epoch. A new policy/candidate gets a different baseline UUID or generation;
// a retry keeps both. Never reuse another candidate's slot or publication.
func sourceObjectNames(i Identity) (string, string, error) {
	if !control.ValidID(i.Source) || i.Epoch < 1 || !validBaselineIdentity(i) {
		return "", "", errors.New("invalid source/baseline namespace")
	}
	id := strings.ReplaceAll(i.Source, "-", "") + fmt.Sprintf("_%d", i.Epoch)
	if i.Baseline != "" {
		data, _ := json.Marshal(struct {
			Source     string
			Epoch      int64
			Baseline   string
			Generation int64
		}{i.Source, i.Epoch, i.Baseline, i.Generation})
		digest := sha256.Sum256(append([]byte("pgws-logical-generation-v1\x00"), data...))
		id = strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:]))
	}
	return "pgws_l_" + id, "pgws_p_" + id, nil
}
