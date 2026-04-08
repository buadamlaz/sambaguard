// Command server is the entry point for the Samba Management Panel.
// It loads configuration, initialises the database, runs migrations, and starts
// the HTTP server with graceful shutdown support.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/buadamlaz/sambaguard/internal/config"
	"github.com/buadamlaz/sambaguard/internal/database"
	"github.com/buadamlaz/sambaguard/internal/handler"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	// ── Configuration ────────────────────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// ── Logger ───────────────────────────────────────────────────────────────
	log, err := buildLogger(cfg)
	if err != nil {
		return fmt.Errorf("build logger: %w", err)
	}
	defer func() { _ = log.Sync() }()

	log.Info("starting SambaGuard — Control, Secure, Monitor",
		zap.String("version", "1.0.0"),
		zap.String("env", cfg.Environment),
		zap.String("listen", cfg.ListenAddr()),
	)

	// ── Database ─────────────────────────────────────────────────────────────
	db, err := database.New(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	if err := database.Migrate(db); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}
	log.Info("database ready", zap.String("path", cfg.DatabasePath))

	// ── Router ───────────────────────────────────────────────────────────────
	router, err := handler.NewRouter(cfg, db, log)
	if err != nil {
		return fmt.Errorf("build router: %w", err)
	}

	// ── HTTP server ───────────────────────────────────────────────────────────
	srv := &http.Server{
		Addr:              cfg.ListenAddr(),
		Handler:           router,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	// ── Signal handling ───────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() {
		log.Info("server listening", zap.String("addr", srv.Addr), zap.Bool("tls", cfg.IsTLS()))
		if cfg.IsTLS() {
			serverErr <- srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			serverErr <- srv.ListenAndServe()
		}
	}()

	select {
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("server error: %w", err)
		}
	case sig := <-quit:
		log.Info("received shutdown signal", zap.String("signal", sig.String()))
	}

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	log.Info("shutting down (30s timeout)...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	log.Info("server stopped cleanly")
	return nil
}

func buildLogger(cfg *config.Config) (*zap.Logger, error) {
	level, err := zapcore.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zapcore.InfoLevel
	}

	var zapCfg zap.Config
	if cfg.Environment == "production" {
		zapCfg = zap.NewProductionConfig()
	} else {
		zapCfg = zap.NewDevelopmentConfig()
		zapCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}
	zapCfg.Level = zap.NewAtomicLevelAt(level)

	return zapCfg.Build()
}
