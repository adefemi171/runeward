package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/adefemi171/runeward/internal/controlplane"
	"github.com/adefemi171/runeward/internal/mcp"
	"github.com/adefemi171/runeward/internal/server"
	"github.com/adefemi171/runeward/web"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

func newServeCmd(configDir *string) *cobra.Command {
	var port int
	var noUI bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the control plane: governed REST API + web dashboard",
		Long: "Start the runeward control plane. Every sandbox tool call is routed\n" +
			"through the policy engine, cost/loop guardrails, and the tamper-evident\n" +
			"audit ledger. Serves the REST API, an approval inbox, an interactive\n" +
			"terminal WebSocket, and (unless --no-ui) the web dashboard.",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, err := controlplane.New(resolveConfigDir(*configDir))
			if err != nil {
				return err
			}
			defer mgr.Close()

			var dashboard http.Handler
			if !noUI {
				dashboard = web.Handler()
			}
			srv := server.New(mgr, dashboard, nil)
			// MCP streamable-HTTP lives at /mcp alongside REST.
			mcpSrv := mcp.NewServer(mgr)
			srv.MCP = mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server { return mcpSrv }, nil)

			addr := fmt.Sprintf(":%d", port)
			httpSrv := &http.Server{Addr: addr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}

			errCh := make(chan error, 1)
			go func() { errCh <- httpSrv.ListenAndServe() }()

			fmt.Fprintf(os.Stderr, "runeward: control plane listening on http://localhost%s\n", addr)
			if !noUI {
				fmt.Fprintf(os.Stderr, "runeward: dashboard at http://localhost%s/\n", addr)
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			select {
			case err := <-errCh:
				if err != nil && err != http.ErrServerClosed {
					return err
				}
				return nil
			case <-ctx.Done():
				fmt.Fprintln(os.Stderr, "\nruneward: shutting down control plane...")
				shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return httpSrv.Shutdown(shutCtx)
			}
		},
	}
	cmd.Flags().IntVar(&port, "port", 8080, "listen port")
	cmd.Flags().BoolVar(&noUI, "no-ui", false, "serve the REST API only, without the web dashboard")
	return cmd
}

func resolveConfigDir(configDir string) string {
	if configDir == "" {
		return os.Getenv("RUNEWARD_CONFIG_DIR")
	}
	return configDir
}

func newMCPCmd(configDir *string) *cobra.Command {
	var asHTTP bool
	var port int
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Run the MCP server wrapping runeward's governed tools (stdio or --http)",
		Long: "Expose runeward's governed sandbox tools over the Model Context Protocol.\n" +
			"By default it speaks stdio (for Claude Desktop / Cursor); with --http it\n" +
			"serves the streamable-HTTP transport at /mcp.",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, err := controlplane.New(resolveConfigDir(*configDir))
			if err != nil {
				return err
			}
			defer mgr.Close()

			mcpSrv := mcp.NewServer(mgr)

			if asHTTP {
				handler := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server { return mcpSrv }, nil)
				mux := http.NewServeMux()
				mux.Handle("/mcp", handler)
				mux.Handle("/mcp/", handler)
				addr := fmt.Sprintf(":%d", port)
				httpSrv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
				errCh := make(chan error, 1)
				go func() { errCh <- httpSrv.ListenAndServe() }()
				fmt.Fprintf(os.Stderr, "runeward: MCP (streamable HTTP) at http://localhost%s/mcp\n", addr)

				ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
				defer stop()
				select {
				case err := <-errCh:
					if err != nil && err != http.ErrServerClosed {
						return err
					}
					return nil
				case <-ctx.Done():
					shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					return httpSrv.Shutdown(shutCtx)
				}
			}

			return mcpSrv.Run(cmd.Context(), &mcpsdk.StdioTransport{})
		},
	}
	cmd.Flags().BoolVar(&asHTTP, "http", false, "serve over streamable HTTP instead of stdio")
	cmd.Flags().IntVar(&port, "port", 8081, "listen port for --http")
	return cmd
}
