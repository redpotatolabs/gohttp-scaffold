package scaffold

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// RunConfig controls the Run helper.
type RunConfig struct {
	// Addr is the listen address. Defaults to ":8080".
	Addr string
	// Handler is the root HTTP handler. Required.
	Handler http.Handler
	// ReadTimeout / WriteTimeout / IdleTimeout default to 5s / 30s / 60s
	// when zero, matching what map and mud use today.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	// ShutdownTimeout is how long Run gives the server to drain when
	// SIGINT/SIGTERM arrive. Defaults to 10s.
	ShutdownTimeout time.Duration
	// OnShutdown is called after the http.Server's Shutdown completes,
	// before Run returns. Optional — use for closing stores, flushing
	// caches, etc.
	OnShutdown func(context.Context)
}

// Run starts an http.Server with the standard redpotatolabs timeouts and
// blocks until SIGINT/SIGTERM, then drains. Fatal startup errors are
// reported via the Server's beacon client.
func (s *Server) Run(ctx context.Context, cfg RunConfig) error {
	if cfg.Handler == nil {
		return errors.New("scaffold: RunConfig.Handler is required")
	}
	addr := cfg.Addr
	if addr == "" {
		addr = ":8080"
	}
	srv := &http.Server{
		Addr:         addr,
		Handler:      cfg.Handler,
		ReadTimeout:  durationOrDefault(cfg.ReadTimeout, 5*time.Second),
		WriteTimeout: durationOrDefault(cfg.WriteTimeout, 30*time.Second),
		IdleTimeout:  durationOrDefault(cfg.IdleTimeout, 60*time.Second),
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		log.Printf("scaffold: listening on %s", addr)
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.Report(ctx, "fatal", fmt.Sprintf("scaffold: listen error: %v", err))
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-stop:
	case <-ctx.Done():
	}

	shutdownTimeout := durationOrDefault(cfg.ShutdownTimeout, 10*time.Second)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("scaffold: shutdown error: %v", err)
	}
	if cfg.OnShutdown != nil {
		cfg.OnShutdown(shutdownCtx)
	}
	return nil
}

func durationOrDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}
