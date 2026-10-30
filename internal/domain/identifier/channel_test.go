package identifier

import (
	"testing"

	"github.com/arafat-hasan/auth1/internal/domain/message"
)

func TestBuiltinChannels(t *testing.T) {
	t.Parallel()
	want := map[string]message.Channel{"email": message.Email, "phone": message.SMS}
	for _, typ := range Builtin() {
		if got := typ.Channel(); got != want[typ.Name()] {
			t.Errorf("%s.Channel() = %q, want %q", typ.Name(), got, want[typ.Name()])
		}
	}
}
