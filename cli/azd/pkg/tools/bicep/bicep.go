// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package bicep

import (
	"context"
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/azure/azure-dev/cli/azd/pkg/exec"
	"github.com/azure/azure-dev/cli/azd/pkg/tools"
	"github.com/blang/semver/v4"
)

type BicepCli interface {
	tools.ExternalTool
	Build(ctx context.Context, file string) (string, error)
}

func NewBicepCli(ctx context.Context) BicepCli {
	return &bicepCli{
		commandRunner: exec.GetCommandRunner(ctx),
	}
}

type bicepCli struct {
	commandRunner exec.CommandRunner
}

var isBicepNotFoundRegex = regexp.MustCompile(`Bicep CLI not found\.`)

func isBicepNotFoundMessage(s string) bool {
	return isBicepNotFoundRegex.MatchString(s)
}

func (cli *bicepCli) Name() string {
	return "Bicep CLI"
}

func (cli *bicepCli) InstallUrl() string {
	return "https://aka.ms/azure-dev/bicep-install"
}

func (cli *bicepCli) versionInfo() tools.VersionInfo {
	return tools.VersionInfo{
		MinimumVersion: semver.Version{
			Major: 0,
			Minor: 8,
			Patch: 9},
		UpdateCommand: "Visit https://aka.ms/azure-dev/bicep-install to upgrade",
	}
}

func (cli *bicepCli) CheckInstalled(ctx context.Context) (bool, error) {
	bicepRes, err := cli.runCommand(ctx, "--version")
	if errors.Is(err, osexec.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("checking %s version: %w", cli.Name(), err)
	}

	bicepSemver, err := tools.ExtractSemver(bicepRes.Stdout)
	if err != nil {
		return false, fmt.Errorf("converting to semver version fails: %w", err)
	}

	updateDetail := cli.versionInfo()
	if bicepSemver.LT(updateDetail.MinimumVersion) {
		return false, &tools.ErrSemver{ToolName: cli.Name(), VersionInfo: updateDetail}
	}

	return true, nil
}

func getBicepCliPath() (string, error) {
	if found, err := osexec.LookPath("bicep"); err == nil {
		return found, nil
	}

	usr, err := user.Current()
	if err != nil {
		return "", osexec.ErrNotFound
	}

	cmdName := "bicep"
	if runtime.GOOS == "windows" {
		cmdName = "bicep.exe"
	}

	candidate := filepath.Join(usr.HomeDir, ".azure", "bin", cmdName)
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}

	return "", osexec.ErrNotFound
}

func (cli *bicepCli) Build(ctx context.Context, file string) (string, error) {
	args := []string{"build", file, "--stdout"}

	buildRes, err := cli.runCommand(ctx, args...)
	if err != nil {
		return "", fmt.Errorf(
			"failed running az bicep build: %s (%w)",
			buildRes.String(),
			err,
		)
	}
	return buildRes.Stdout, nil
}

func (cli *bicepCli) runCommand(ctx context.Context, args ...string) (exec.RunResult, error) {
	bicepPath, err := getBicepCliPath()
	if err != nil {
		return exec.RunResult{}, err
	}

	runArgs := exec.NewRunArgs(bicepPath, args...)
	return cli.commandRunner.Run(ctx, runArgs)
}

type contextKey string

const (
	bicepContextKey contextKey = "bicepcli"
)

func GetBicepCli(ctx context.Context) BicepCli {
	cli, ok := ctx.Value(bicepContextKey).(BicepCli)
	if !ok {
		cli = NewBicepCli(ctx)
	}

	return cli
}
