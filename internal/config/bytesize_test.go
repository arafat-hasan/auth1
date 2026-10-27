package config

import "testing"

func TestParseByteSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    ByteSize
		wantErr bool
	}{
		{in: "0", want: 0},
		{in: "100", want: 100},
		{in: "1KiB", want: 1024},
		{in: "64MiB", want: 67108864},
		{in: "19MiB", want: 19922944},
		{in: "2GiB", want: 2147483648},
		{in: "", wantErr: true},
		{in: "64mib", wantErr: true},
		{in: "1.5GiB", wantErr: true},
		{in: "-1MiB", wantErr: true},
		{in: "+1MiB", wantErr: true},
		{in: "64 MiB", wantErr: true},
		{in: " 64MiB", wantErr: true},
		{in: "64MB", wantErr: true},
		{in: "MiB", wantErr: true},
		{in: "99999999999GiB", wantErr: true},
		{in: "99999999999999999999", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := ParseByteSize(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseByteSize(%q) = %d, want an error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseByteSize(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseByteSize(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestByteSizeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   ByteSize
		want string
	}{
		{in: 0, want: "0"},
		{in: 100, want: "100"},
		{in: 1536 * KiB, want: "1536KiB"},
		{in: 64 * MiB, want: "64MiB"},
		{in: 2 * GiB, want: "2GiB"},
	}
	for _, tt := range tests {
		if got := tt.in.String(); got != tt.want {
			t.Errorf("ByteSize(%d).String() = %q, want %q", int64(tt.in), got, tt.want)
		}
	}
}

func TestByteSizeText(t *testing.T) {
	t.Parallel()

	var b ByteSize
	if err := b.UnmarshalText([]byte("19MiB")); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if b != 19*MiB {
		t.Errorf("UnmarshalText(19MiB) = %d, want %d", b, 19*MiB)
	}
	text, err := b.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if string(text) != "19MiB" {
		t.Errorf("MarshalText = %q, want %q", text, "19MiB")
	}
	if err := b.UnmarshalText([]byte("19mb")); err == nil {
		t.Error("UnmarshalText(19mb): want an error")
	}
}

func FuzzParseByteSize(f *testing.F) {
	for _, s := range []string{"0", "100", "1KiB", "64MiB", "2GiB", "1.5GiB", "-1", "9223372036854775807"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		b, err := ParseByteSize(s)
		if err != nil {
			return
		}
		if b < 0 {
			t.Fatalf("ParseByteSize(%q) = %d, negative", s, b)
		}
		again, err := ParseByteSize(b.String())
		if err != nil {
			t.Fatalf("ParseByteSize(%q) after String of %q: %v", b.String(), s, err)
		}
		if again != b {
			t.Fatalf("round trip of %q: %d then %d", s, b, again)
		}
	})
}
