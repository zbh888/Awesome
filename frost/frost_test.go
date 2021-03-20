package frost_test

import (
	"github/zbh888/awsome/frost"
	"testing"
)

func TestRunnable(t *testing.T) {
	_, _ = frost.KeyGen_send(3, 4, 10, "123")
}
