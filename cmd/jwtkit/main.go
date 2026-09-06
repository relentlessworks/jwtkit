package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/relentlessworks/jwtkit/internal/api"
	"github.com/relentlessworks/jwtkit/internal/config"
	"github.com/relentlessworks/jwtkit/internal/store"
)

func main() {
	cfg := config.Load()

	s, err := store.New(cfg.DataFile)
	if err != nil {
		log.Fatalf("failed to open data store at %s: %v", cfg.DataFile, err)
	}
	defer s.Close()

	h := api.New(s, cfg)

	mux := http.NewServeMux()
	h.Register(mux)

	addr := fmt.Sprintf(":%d", cfg.Port)

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		s.Close()
		os.Exit(0)
	}()

	log.Printf("jwtkit listening on %s (dev_mode=%v, data=%s)", addr, cfg.DevMode, cfg.DataFile)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
