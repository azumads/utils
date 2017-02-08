package utils

import "log"

// utils.RecoverGo(func() {...})
func RecoverGo(f func()) {
	go func() {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("Panic recovery from goroutine -> %s\n", err)
			}
		}()
		f()
	}()
}
