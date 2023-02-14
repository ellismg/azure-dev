package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/azure/azure-dev/cli/azd/cmd/actions"
	"github.com/azure/azure-dev/cli/azd/internal"
	"github.com/azure/azure-dev/cli/azd/pkg/output"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func newAuthServerCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "server",
		Hidden: true,
	}
}

type authServerFlags struct {
	port   int
	global *internal.GlobalCommandOptions
	shell  bool
}

func newAuthServerFlags(cmd *cobra.Command, global *internal.GlobalCommandOptions) *authServerFlags {
	flags := &authServerFlags{}
	flags.Bind(cmd.Flags(), global)

	return flags
}

func (f *authServerFlags) Bind(local *pflag.FlagSet, global *internal.GlobalCommandOptions) {
	f.global = global
	local.IntVar(&f.port, "port", 0, "The port to listen on (0 for a randomly assigned port).")
	local.BoolVar(&f.shell, "shell", false, "Launch a shell and set env vars for auth.")
}

func newAuthServerAction(
	credentialProvider CredentialProviderFn,
	formatter output.Formatter,
	writer io.Writer,
	flags *authServerFlags,
) actions.Action {
	return &authServerAction{
		credentialProvider: credentialProvider,
		formatter:          formatter,
		writer:             writer,
		flags:              flags,
	}
}

type authServerAction struct {
	credentialProvider CredentialProviderFn
	formatter          output.Formatter
	writer             io.Writer
	flags              *authServerFlags
}

func (a *authServerAction) Run(ctx context.Context) (*actions.ActionResult, error) {
	cred, err := a.credentialProvider(ctx, nil)
	if err != nil {
		return nil, err
	}

	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", a.flags.port))
	if err != nil {
		return nil, err
	}

	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return nil, err
	}

	token := base64.RawURLEncoding.EncodeToString(entropy)

	mux := http.NewServeMux()

	// Open a server on an ephemeral port and wait for a POST request to the /api/token endpoint.
	mux.HandleFunc("/api/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if r.Header.Get("Authorization") != token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var reqCtx struct {
			Scopes          []string `json:"scopes"`
			ParentRequestId *string  `json:"parentRequestId,omitempty"`
			Claims          *string  `json:"claims,omitempty"`
			TenantId        *string  `json:"tenantId,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&reqCtx); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		tok, err := cred.GetToken(r.Context(), policy.TokenRequestOptions{
			Scopes: reqCtx.Scopes,
		})

		// TODO: Figure out a way to return an error?
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		res, err := json.Marshal(struct {
			Token     string `json:"token"`
			ExpiresOn string `json:"expiresOn"`
		}{
			Token:     tok.Token,
			ExpiresOn: tok.ExpiresOn.Format(time.RFC3339),
		})

		if err != nil {
			panic(err)
		}

		w.WriteHeader(http.StatusOK)
		w.Write(res)
	})

	srv := http.Server{
		Handler: mux,
	}

	if a.flags.shell {
		var cmd exec.Cmd

		if runtime.GOOS == "windows" {
			cmd.Path = os.Getenv("COMSPEC")
		} else {
			cmd.Path = "/bin/sh"
		}

		cmd.Env = append(os.Environ(),
			fmt.Sprintf("AUTH_PROTOCOL_ENDPOINT=http://%s/api/token", l.Addr().String()),
			fmt.Sprintf("AUTH_PROTOCOL_TOKEN=%s", token))

		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		go srv.Serve(l)

		return nil, cmd.Run()
	} else {
		_, _ = fmt.Fprintf(a.writer, "Listening on %s, token: %s\n", l.Addr().String(), token)

		return nil, srv.Serve(l)
	}
}
