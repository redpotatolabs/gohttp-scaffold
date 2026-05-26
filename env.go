package scaffold

import "os"

// EnvOrDefault returns os.Getenv(key) when non-empty, else fallback.
func EnvOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
