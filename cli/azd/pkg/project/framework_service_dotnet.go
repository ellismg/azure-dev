// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package project

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/azure/azure-dev/cli/azd/pkg/async"
	"github.com/azure/azure-dev/cli/azd/pkg/environment"
	"github.com/azure/azure-dev/cli/azd/pkg/exec"
	"github.com/azure/azure-dev/cli/azd/pkg/infra/provisioning"
	"github.com/azure/azure-dev/cli/azd/pkg/tools"
	"github.com/azure/azure-dev/cli/azd/pkg/tools/dotnet"
)

type dotnetProject struct {
	env       *environment.Environment
	dotnetCli dotnet.DotNetCli
}

// NewDotNetProject creates a new instance of a dotnet project
func NewDotNetProject(
	commandRunner exec.CommandRunner, env *environment.Environment,
) FrameworkService {
	return &dotnetProject{
		env:       env,
		dotnetCli: dotnet.NewDotNetCli(commandRunner),
	}
}

// Gets the required external tools for the project
func (dp *dotnetProject) RequiredExternalTools(context.Context) []tools.ExternalTool {
	return []tools.ExternalTool{dp.dotnetCli}
}

// Initializes the dotnet project
func (dp *dotnetProject) Initialize(ctx context.Context, serviceConfig *ServiceConfig) error {
	projFile, err := findProjectFile(serviceConfig.Path(), serviceConfig.DotnetProjectFile)
	if err != nil {
		return err
	}
	if err := dp.dotnetCli.InitializeSecret(ctx, projFile[0]); err != nil {
		return err
	}
	handler := func(ctx context.Context, args ServiceLifecycleEventArgs) error {
		return dp.setUserSecretsFromOutputs(ctx, serviceConfig, args)
	}
	if err := serviceConfig.AddHandler(ServiceEventEnvUpdated, handler); err != nil {
		return err
	}

	return nil
}

// Restores the dependencies for the project
func (dp *dotnetProject) Restore(
	ctx context.Context,
	serviceConfig *ServiceConfig,
) *async.TaskWithProgress[*ServiceRestoreResult, ServiceProgress] {
	return async.RunTaskWithProgress(
		func(task *async.TaskContextWithProgress[*ServiceRestoreResult, ServiceProgress]) {
			projFile, err := findProjectFile(serviceConfig.Path(), serviceConfig.DotnetProjectFile)
			if err != nil {
				task.SetError(err)
				return
			}
			if err := dp.dotnetCli.Restore(ctx, projFile[0]); err != nil {
				task.SetError(err)
				return
			}

			task.SetResult(&ServiceRestoreResult{})
		},
	)
}

// Builds the dotnet project using the dotnet CLI
func (dp *dotnetProject) Build(
	ctx context.Context,
	serviceConfig *ServiceConfig,
	restoreOutput *ServiceRestoreResult,
) *async.TaskWithProgress[*ServiceBuildResult, ServiceProgress] {
	return async.RunTaskWithProgress(
		func(task *async.TaskContextWithProgress[*ServiceBuildResult, ServiceProgress]) {
			publishRoot, err := os.MkdirTemp("", "azd")
			if err != nil {
				task.SetError(fmt.Errorf("creating package directory for %s: %w", serviceConfig.Name, err))
				return
			}

			task.SetProgress(NewServiceProgress("Creating deployment package"))
			projFile, err := findProjectFile(serviceConfig.Path(), serviceConfig.DotnetProjectFile)
			if err != nil {
				task.SetError(err)
				return
			}
			if err := dp.dotnetCli.Publish(ctx, projFile[0], publishRoot); err != nil {
				task.SetError(err)
				return
			}

			if serviceConfig.OutputPath != "" {
				publishRoot = filepath.Join(publishRoot, serviceConfig.OutputPath)
			}

			task.SetResult(&ServiceBuildResult{
				Restore:         restoreOutput,
				BuildOutputPath: publishRoot,
			})
		},
	)
}

func (dp *dotnetProject) setUserSecretsFromOutputs(
	ctx context.Context,
	serviceConfig *ServiceConfig,
	args ServiceLifecycleEventArgs,
) error {
	bicepOutputArgs := args.Args["bicepOutput"]
	if bicepOutputArgs == nil {
		log.Println("no bicep outputs set as secrets to dotnet project, map args.Args doesn't contain key \"bicepOutput\"")
		return nil
	}

	bicepOutput, ok := bicepOutputArgs.(map[string]provisioning.OutputParameter)
	if !ok {
		return fmt.Errorf("fail on interface conversion: no type in map")
	}

	for key, val := range bicepOutput {
		if err := dp.dotnetCli.SetSecret(
			ctx,
			normalizeDotNetSecret(key),
			fmt.Sprint(val.Value),
			serviceConfig.Path(),
		); err != nil {
			return err
		}
	}
	return nil
}

func normalizeDotNetSecret(key string) string {
	// dotnet recognizes "__" as the hierarchy key separator for environment variables, but for user secrets, it has to be
	// ":".
	return strings.ReplaceAll(key, "__", ":")
}

func findProjectFile(path string, dotnetProjectFile string) ([]string, error) {
	files, err := filepath.Glob(path + "/*proj")
	if err != nil {
		return files, fmt.Errorf("error: checking project file in %s: %s", path, err)
	}
	if len(files) == 0 {
		return files, fmt.Errorf("no project file (.csproj or .vbproj or .fsproj) found")
	} else if len(files) > 1 && dotnetProjectFile == "" {
		return files, fmt.Errorf("there are multiple project files in %s. "+
			"Please add the project file path with row 'dotnetProjectFile' in azure.yaml", path)
	} else if len(files) > 1 && dotnetProjectFile != "" {
		files = []string{dotnetProjectFile}
	}
	return files, err
}
