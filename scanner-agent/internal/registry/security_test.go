package registry

import "testing"

func TestValidateRegistryRejectsPrivateAddresses(t *testing.T) {
	for _, host := range []string{
		"127.0.0.1",
		"10.0.0.8:5000",
		"169.254.169.254",
		"[::1]:443",
	} {
		if err := validateRegistry(host); err == nil {
			t.Errorf("validateRegistry(%q) unexpectedly succeeded", host)
		}
	}
}

func TestValidateTokenRealmRequiresSafeHTTPS(t *testing.T) {
	for _, realm := range []string{
		"http://auth.example/token",
		"https://127.0.0.1/token",
		"https://user:pass@auth.example/token",
	} {
		if _, err := validateTokenRealm(realm); err == nil {
			t.Errorf("validateTokenRealm(%q) unexpectedly succeeded", realm)
		}
	}
}
