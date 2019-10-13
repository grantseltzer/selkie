package entitlements

import (
	"log"
	"os"
)

func logIfEnabled(format string, v ...interface{}) {
	if os.Getenv("SELKIE_LOG") != "" {
		log.Printf("[selkie] "+format, v...)
	}
}
