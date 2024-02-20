package iphelper

import (
	"testing"
)

func check(t *testing.T, s1, s2 string, i1, i2 int) {
	ip, port, version, err := ParseEndpoint(s1)
	if err != nil {
		t.Fatalf("failed to parse \"%s\": %s", s1, err)
		return
	}
	if ip != s2 {
		t.Fatalf("parsing %s: mismatch, got \"%s\", expected \"%s\"\n", s1, ip, s2)
		return
	}
	if port != uint32(i1) {
		t.Fatalf("parsing %s: mismatch, got port %d, expected %d\n", s1, port, i1)
		return
	}
	if version != i2 {
		t.Fatalf("parsing %s: mismatch, got version %d, expected %d\n", s1, version, i2)
		return
	}
}

func Test1(t *testing.T) {
	check(t, "172.29.1.5:1420", "172.29.1.5", 1420, 4)
	check(t, "10.1.1.1:53", "10.1.1.1", 53, 4)
	check(t, "10.1.1.1", "10.1.1.1", 0, 4)
	check(t, "fe80::9e6b:ff:fe10:52c5", "fe80::9e6b:ff:fe10:52c5", 0, 6)
	check(t, "[fe80::9e6b:ff:fe10:52c5]:53", "fe80::9e6b:ff:fe10:52c5", 53, 6)
}
