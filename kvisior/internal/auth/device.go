package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DeviceCookieName = "kv8_device"

	deviceCookieTTL = 180 * 24 * time.Hour
	deviceKeyEnv    = "KVISIOR_DEVICE_COOKIE_KEY"
)

func loadDeviceKey() []byte {
	if v := strings.TrimSpace(os.Getenv(deviceKeyEnv)); v != "" {
		if key, err := hex.DecodeString(v); err == nil && len(key) >= 32 {
			return key
		}
		log.Printf("[auth] %s must be at least 32 bytes of hex — falling back to a random per-process key", deviceKeyEnv)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return key
}

func (m *Manager) deviceMAC(username, nonce, expiry string) string {
	mac := hmac.New(sha256.New, m.deviceKey)
	mac.Write([]byte(username + "\x00" + nonce + "\x00" + expiry))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *Manager) trustedDevice(r *http.Request, username string) (string, bool) {
	c, err := r.Cookie(DeviceCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 {
		return "", false
	}
	nonce, expiry, sig := parts[0], parts[1], parts[2]
	exp, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return "", false
	}
	if !hmac.Equal([]byte(sig), []byte(m.deviceMAC(username, nonce, expiry))) {
		return "", false
	}
	return nonce, true
}

func (m *Manager) setDeviceCookie(w http.ResponseWriter, username string) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return
	}
	nonce := hex.EncodeToString(b)
	expiresAt := time.Now().Add(deviceCookieTTL)
	expiry := strconv.FormatInt(expiresAt.Unix(), 10)
	http.SetCookie(w, &http.Cookie{
		Name:     DeviceCookieName,
		Value:    nonce + "." + expiry + "." + m.deviceMAC(username, nonce, expiry),
		Path:     "/auth/login",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   m.secureCookie,
		SameSite: http.SameSiteStrictMode,
	})
}
