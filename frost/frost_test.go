package frost_test

import (
	"github/zbh888/awsome/frost"
	"testing"
)

func TestRunnable(t *testing.T) {
	// require threshold >= 1
	_, _ = frost.KeyGen_send(1, 1, 0, "123")
	_, _ = frost.KeyGen_send(1, 1, 10, "123")
	_, _ = frost.KeyGen_send(2, 12, 10, "123")
}
