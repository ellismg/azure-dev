// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/azure/azure-dev/cli/azd/pkg/config"
)

// TODO(azure/azure-dev#710): Right now, we re-use the App Id of the `az` CLI, until we have our own.
//
// nolint:lll
// https://github.com/Azure/azure-cli/blob/azure-cli-2.41.0/src/azure-cli-core/azure/cli/core/auth/identity.py#L23
const cAZD_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

// cCurrentUserKey is the key we use in config for the storing identity information of the currently logged in user.
const cCurrentUserKey = "auth.account.currentUser"

// The scopes to request when acquiring our token during the login flow.
var cLoginScopes = []string{"https://management.azure.com//.default"}

// authDirectoryFileMode is the file mode used to create the folder that is used for auth folder and sub-folders.
const authDirectoryFileMode = 0700

type Manager struct {
	out             io.Writer
	publicClient    *public.Client
	configManager   config.Manager
	credentialCache cache.ExportReplace
}

func NewManager(out io.Writer, configManager config.Manager) (*Manager, error) {
	cfgRoot, err := config.GetUserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("getting config dir: %w", err)
	}

	authRoot := filepath.Join(cfgRoot, "auth")
	if err := os.MkdirAll(authRoot, authDirectoryFileMode); err != nil {
		return nil, fmt.Errorf("creating auth root: %w", err)
	}

	cacheRoot := filepath.Join(authRoot, "msal")
	if err := os.MkdirAll(cacheRoot, authDirectoryFileMode); err != nil {
		return nil, fmt.Errorf("creating msal cache root: %w", err)
	}

	publicClientApp, err := public.New(cAZD_CLIENT_ID, public.WithCache(newCache(cacheRoot)))
	if err != nil {
		return nil, fmt.Errorf("creating msal client: %w", err)
	}

	return &Manager{
		out:             out,
		publicClient:    &publicClientApp,
		configManager:   configManager,
		credentialCache: newCredentialCache(authRoot),
	}, nil
}

var ErrNoCurrentUser = errors.New("not logged in, run `azd login` to login")

func (m *Manager) GetCredentialForCurrentUser(ctx context.Context) (azcore.TokenCredential, error) {
	_, cred, _, err := m.GetSignedInUser(ctx)
	return cred, err
}

func (m *Manager) GetSignedInUser(ctx context.Context) (*public.Account, azcore.TokenCredential, *time.Time, error) {
	cfg, err := config.GetUserConfig(m.configManager)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fetching current user: %w", err)
	}

	currentUser, has := cfg.Get(cCurrentUserKey)
	if !has {
		return nil, nil, nil, ErrNoCurrentUser
	}

	currentUserData, ok := currentUser.(map[string]any)
	if !ok {
		log.Println("current user data is corrupted, ignoring")
		return nil, nil, nil, ErrNoCurrentUser
	}

	if _, has := currentUserData["homeId"]; has {
		currentUserHomeId := currentUserData["homeId"].(string)

		for _, account := range m.publicClient.Accounts() {
			if account.HomeAccountID == currentUserHomeId {
				cred := newAzdCredential(m.publicClient, &account)
				if tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: cLoginScopes}); err != nil {
					return nil, nil, nil, fmt.Errorf("failed to get token: %v: %w", err, ErrNoCurrentUser)
				} else {
					return &account, cred, &tok.ExpiresOn, nil
				}
			}

			log.Printf("ignoring cached account with home id '%s', does not match '%s'",
				account.HomeAccountID, currentUserHomeId)
		}
	} else if _, has := currentUserData["clientId"]; has {
		var secret fixedMarshaller

		m.credentialCache.Replace(&secret,
			fmt.Sprintf("%s.%s", currentUserData["tenantId"].(string), currentUserData["clientId"].(string)),
		)

		if len(secret.val) == 0 {
			return nil, nil, nil, ErrNoCurrentUser
		}

		return m.LoginWithServicePrincipal(
			ctx,
			currentUserData["tenantId"].(string),
			currentUserData["clientId"].(string),
			string(secret.val))
	}

	return nil, nil, nil, ErrNoCurrentUser
}

func (m *Manager) Login(
	ctx context.Context,
	useDeviceCode bool,
) (*public.Account, azcore.TokenCredential, *time.Time, error) {

	var authResult public.AuthResult

	if useDeviceCode {
		code, err := m.publicClient.AcquireTokenByDeviceCode(ctx, cLoginScopes)
		if err != nil {
			return nil, nil, nil, err
		}

		fmt.Fprintln(m.out, code.Result.Message)

		res, err := code.AuthenticationResult(ctx)
		if err != nil {
			return nil, nil, nil, err
		}

		authResult = res
	} else {
		res, err := m.publicClient.AcquireTokenInteractive(ctx, cLoginScopes)
		if err != nil {
			return nil, nil, nil, err
		}

		authResult = res
	}

	if err := m.saveCurrentUserProperties(map[string]any{"homeId": authResult.Account.HomeAccountID}); err != nil {
		return nil, nil, nil, err
	}

	log.Printf("logged in as %s (%s)", authResult.Account.PreferredUsername, authResult.Account.HomeAccountID)

	return &authResult.Account, newAzdCredential(m.publicClient, &authResult.Account), &authResult.ExpiresOn, nil
}

func (m *Manager) saveCurrentUserProperties(properties map[string]any) error {
	cfg, err := config.GetUserConfig(m.configManager)
	if err != nil {
		return fmt.Errorf("fetching current user: %w", err)
	}

	if err := cfg.Set(cCurrentUserKey, properties); err != nil {
		return fmt.Errorf("setting account id in config: %w", err)
	}

	userConfigFilePath, err := config.GetUserConfigFilePath()
	if err != nil {
		return fmt.Errorf("failed getting user config file path. %w", err)
	}

	if err := m.configManager.Save(cfg, userConfigFilePath); err != nil {
		return fmt.Errorf("failed saving configuration: %w", err)
	}

	return nil
}

func (m *Manager) LoginWithServicePrincipal(
	ctx context.Context, tenantId, clientId, clientSecret string,
) (*public.Account, azcore.TokenCredential, *time.Time, error) {

	cred, err := azidentity.NewClientSecretCredential(tenantId, clientId, clientSecret, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating credential: %w", err)
	}

	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: cLoginScopes,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fetching token: %w", err)
	}

	m.credentialCache.Export(&fixedMarshaller{
		val: []byte(clientSecret),
	},
		fmt.Sprintf("%s.%s", tenantId, clientId),
	)

	if err := m.saveCurrentUserProperties(map[string]any{
		"tenantId": tenantId,
		"clientId": clientId,
	}); err != nil {
		return nil, nil, nil, err
	}

	return nil, cred, &tok.ExpiresOn, nil
}

func (m *Manager) Logout(ctx context.Context) error {
	act, _, _, err := m.GetSignedInUser(ctx)
	if errors.Is(err, ErrNoCurrentUser) {
		// already signed out, that's okay
		return nil
	} else if err != nil {
		return fmt.Errorf("fetching current user: %w", err)
	}

	if act != nil {
		if err := m.publicClient.RemoveAccount(*act); err != nil {
			log.Printf("error removing account from msal cache during logout. ignoring: %v", err)
		}
	}

	// Unset the current user from config, but if we fail to do so, don't fail the overall operation
	cfg, err := config.GetUserConfig(m.configManager)
	if err != nil {
		log.Printf("error fetching config for current user during logout. ignoring: %v", err)
		return nil
	}

	if cur, has := cfg.Get(cCurrentUserKey); has {
		// When logged in as a service principal, remove the cached credential
		if props, ok := cur.(map[string]any); ok {
			clientId, _ := props["clientId"]
			tenantId, _ := props["tenantId"]

			if clientId != "" && tenantId != "" {
				m.credentialCache.Export(&fixedMarshaller{
					val: []byte{},
				},
					fmt.Sprintf("%s.%s", tenantId, clientId),
				)
			}
		}
	}

	if err := cfg.Unset(cCurrentUserKey); err != nil {
		log.Printf("error un-setting key current user during logout. ignoring: %v", err)
	}

	if path, err := config.GetUserConfigFilePath(); err != nil {
		log.Printf("error getting user config path during logout. ignoring: %v", err)
	} else {
		return m.configManager.Save(cfg, path)
	}

	return nil
}
