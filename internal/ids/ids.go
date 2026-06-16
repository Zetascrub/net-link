package ids

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// New returns a time-prefixed random ID: prefix_<12-hex-ms><16-hex-random>.
// IDs sort lexicographically by creation time, which keeps run files ordered.
func New(prefix string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%s_%012x%016x", prefix, time.Now().UnixMilli(), 0)
	}
	return fmt.Sprintf("%s_%012x%s", prefix, time.Now().UnixMilli(), hex.EncodeToString(b[:]))
}
