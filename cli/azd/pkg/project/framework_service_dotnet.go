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

	"github.com/azure/azure-dev/cli/azd/pkg/environment"
	"github.com/azure/azure-dev/cli/azd/pkg/infra/provisioning"
	"github.com/azure/azure-dev/cli/azd/pkg/input"
	"github.com/azure/azure-dev/cli/azd/pkg/tools"
	"github.com/azure/azure-dev/cli/azd/pkg/tools/dotnet"
)

const (
	defaultDotNetBuildConfiguration string = "Release"
)

type dotnetProject struct {
	env       *environment.Environment
	dotnetCli dotnet.DotNetCli
	console   input.Console
}

// NewDotNetProject creates a new instance of a dotnet project
func NewDotNetProject(
	dotNetCli dotnet.DotNetCli,
	env *environment.Environment,
	console input.Console,
) FrameworkService {
	return &dotnetProject{
		env:       env,
		dotnetCli: dotNetCli,
		console:   console,
	}
}

func (dp *dotnetProject) Requirements() FrameworkRequirements {
	return FrameworkRequirements{
		// dotnet will automatically restore & build the project if needed
		Package: FrameworkPackageRequirements{
			RequireRestore: false,
			RequireBuild:   false,
		},
	}
}

// Gets the required external tools for the project
func (dp *dotnetProject) RequiredExternalTools(context.Context) []tools.ExternalTool {
	return []tools.ExternalTool{dp.dotnetCli}
}

// Initializes the dotnet project
func (dp *dotnetProject) Initialize(ctx context.Context, serviceConfig *ServiceConfig) error {
	projFile, err := findProjectFile(serviceConfig.Name, serviceConfig.Path())
	if err != nil {
		return err
	}
	if err := dp.dotnetCli.InitializeSecret(ctx, projFile); err != nil {
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
) (*ServiceRestoreResult, error) {

	dp.console.Progress(ctx, "Restoring .NET project dependencies")
	projFile, err := findProjectFile(serviceConfig.Name, serviceConfig.Path())
	if err != nil {
		return nil, err
	}
	if err := dp.dotnetCli.Restore(ctx, projFile); err != nil {
		return nil, err
	}

	return &ServiceRestoreResult{}, nil

}

// Builds the dotnet project using the dotnet CLI
func (dp *dotnetProject) Build(
	ctx context.Context,
	serviceConfig *ServiceConfig,
	restoreOutput *ServiceRestoreResult,
) (*ServiceBuildResult, error) {

	dp.console.Progress(ctx, "Building .NET project")
	projFile, err := findProjectFile(serviceConfig.Name, serviceConfig.Path())
	if err != nil {
		return nil, err
	}
	if err := dp.dotnetCli.Build(ctx, projFile, defaultDotNetBuildConfiguration, ""); err != nil {
		return nil, err
	}

	defaultOutputDir := filepath.Join("./bin", defaultDotNetBuildConfiguration)

	// Attempt to find the default build output location
	buildOutputDir := serviceConfig.Path()
	_, err = os.Stat(filepath.Join(buildOutputDir, defaultOutputDir))
	if err == nil {
		buildOutputDir = filepath.Join(buildOutputDir, defaultOutputDir)
	}

	// By default dotnet build will create a sub folder for the project framework version, etc. net6.0
	// If we have a single folder under build configuration assume this location as build output result
	subDirs, err := os.ReadDir(buildOutputDir)
	if err == nil {
		if len(subDirs) == 1 {
			buildOutputDir = filepath.Join(buildOutputDir, subDirs[0].Name())
		}
	}

	return &ServiceBuildResult{
		Restore:         restoreOutput,
		BuildOutputPath: buildOutputDir,
	}, nil

}

func (dp *dotnetProject) Package(
	ctx context.Context,
	serviceConfig *ServiceConfig,
	buildOutput *ServiceBuildResult,
) (*ServicePackageResult, error) {

	packageDest, err := os.MkdirTemp("", "azd")
	if err != nil {
		return nil, fmt.Errorf("creating package directory for %s: %w", serviceConfig.Name, err)
	}

	dp.console.Progress(ctx, "Publishing .NET project")
	projFile, err := findProjectFile(serviceConfig.Name, serviceConfig.Path())
	if err != nil {
		return nil, err
	}
	if err := dp.dotnetCli.Publish(ctx, projFile, defaultDotNetBuildConfiguration, packageDest); err != nil {
		return nil, err
	}

	if serviceConfig.OutputPath != "" {
		packageDest = filepath.Join(packageDest, serviceConfig.OutputPath)
	}

	if err := validatePackageOutput(packageDest); err != nil {
		return nil, err
	}

	return &ServicePackageResult{
		Build:       buildOutput,
		PackagePath: packageDest,
	}, nil

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

	secrets := map[string]string{}

	for key, val := range bicepOutput {
		secrets[normalizeDotNetSecret(key)] = fmt.Sprint(val.Value)
	}

	if err := dp.dotnetCli.SetSecrets(ctx, secrets, serviceConfig.Path()); err != nil {
		return fmt.Errorf("failed to set secrets: %w", err)
	}

	return nil
}

func normalizeDotNetSecret(key string) string {
	// dotnet recognizes "__" as the hierarchy key separator for environment variables, but for user secrets, it has to be
	// ":".
	return strings.ReplaceAll(key, "__", ":")
}

/* findProjectFile locates the project file to pass to the `dotnet` tool for a given dotnet service.
**
** projectPath is either a path to a directory, or to a project file. When projectPath is a directory,
** the first file matching the glob expression *.*proj (what dotnet expects) is returned.
** If multiple files match, an error is returned.
 */

func findProjectFile(serviceName string, projectPath string) (string, error) {
	info, err := os.Stat(projectPath)
	if err != nil {
		return "", err
	}

	if !info.IsDir() {
		return projectPath, nil
	}
	files, err := filepath.Glob(filepath.Join(projectPath, "*.*proj"))
	if err != nil {
		return "", fmt.Errorf("searching for project file: %w", err)
	}
	if len(files) == 0 {
		return "", fmt.Errorf(
			"could not locate a dotnet project file for service %s in %s. Update the project setting of "+
				"azure.yaml for service %s to be the path to the dotnet project for this service",
			serviceName, projectPath, serviceName)
	} else if len(files) > 1 {
		return "", fmt.Errorf(
			"could not locate a dotnet project file for service %s in %s. Multiple project files exist. Update "+
				"the \"project\" setting of azure.yaml for service %s to be the path to the dotnet project to use for this "+
				"service",
			serviceName, projectPath, serviceName)
	}

	return files[0], nil
}
