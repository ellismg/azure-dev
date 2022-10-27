// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package cmd

import (
	"github.com/azure/azure-dev/cli/azd/cmd/actions"
	"github.com/azure/azure-dev/cli/azd/internal"
	"github.com/azure/azure-dev/cli/azd/pkg/account"
	"github.com/azure/azure-dev/cli/azd/pkg/auth"
	"github.com/azure/azure-dev/cli/azd/pkg/config"
	"github.com/azure/azure-dev/cli/azd/pkg/output"
	"github.com/azure/azure-dev/cli/azd/pkg/templates"
	"github.com/azure/azure-dev/cli/azd/pkg/tools/git"
	"github.com/spf13/cobra"
)

import (
	_ "github.com/azure/azure-dev/cli/azd/pkg/infra/provisioning/bicep"
	_ "github.com/azure/azure-dev/cli/azd/pkg/infra/provisioning/terraform"
)

// Injectors from wire.go:

func initDeployAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags deployFlags, args []string) (actions.Action, error) {
	azdContext, err := newAzdContext()
	if err != nil {
		return nil, err
	}
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	console := newConsoleFromOptions(o, formatter, writer, cmd)
	commandRunner := newCommandRunnerFromConsole(console)
	manager := config.NewManager()
	authManager, err := auth.NewManager(writer, manager)
	if err != nil {
		return nil, err
	}
	tokenCredential, err := newCredential(authManager)
	if err != nil {
		return nil, err
	}
	azCli := newAzCliFromOptions(o, commandRunner, tokenCredential)
	cmdDeployAction, err := newDeployAction(flags, azdContext, azCli, console, formatter, writer)
	if err != nil {
		return nil, err
	}
	return cmdDeployAction, nil
}

func initInitAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags initFlags, args []string) (actions.Action, error) {
	azdContext, err := newAzdContext()
	if err != nil {
		return nil, err
	}
	manager := config.NewManager()
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	console := newConsoleFromOptions(o, formatter, writer, cmd)
	commandRunner := newCommandRunnerFromConsole(console)
	authManager, err := auth.NewManager(writer, manager)
	if err != nil {
		return nil, err
	}
	tokenCredential, err := newCredential(authManager)
	if err != nil {
		return nil, err
	}
	azCli := newAzCliFromOptions(o, commandRunner, tokenCredential)
	accountManager, err := account.NewManager(manager, azCli)
	if err != nil {
		return nil, err
	}
	gitCli := git.NewGitCliFromRunner(commandRunner)
	cmdInitAction, err := newInitAction(azdContext, accountManager, commandRunner, console, azCli, gitCli, flags)
	if err != nil {
		return nil, err
	}
	return cmdInitAction, nil
}

func initLoginAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags loginFlags, args []string) (actions.Action, error) {
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	manager := config.NewManager()
	authManager, err := auth.NewManager(writer, manager)
	if err != nil {
		return nil, err
	}
	console := newConsoleFromOptions(o, formatter, writer, cmd)
	cmdLoginAction := newLoginAction(formatter, writer, authManager, flags, console)
	return cmdLoginAction, nil
}

func initUpAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags upFlags, args []string) (actions.Action, error) {
	azdContext, err := newAzdContext()
	if err != nil {
		return nil, err
	}
	manager := config.NewManager()
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	console := newConsoleFromOptions(o, formatter, writer, cmd)
	commandRunner := newCommandRunnerFromConsole(console)
	authManager, err := auth.NewManager(writer, manager)
	if err != nil {
		return nil, err
	}
	tokenCredential, err := newCredential(authManager)
	if err != nil {
		return nil, err
	}
	azCli := newAzCliFromOptions(o, commandRunner, tokenCredential)
	accountManager, err := account.NewManager(manager, azCli)
	if err != nil {
		return nil, err
	}
	gitCli := git.NewGitCliFromRunner(commandRunner)
	cmdInitFlags := flags.initFlags
	cmdInitAction, err := newInitAction(azdContext, accountManager, commandRunner, console, azCli, gitCli, cmdInitFlags)
	if err != nil {
		return nil, err
	}
	cmdInfraCreateFlags := flags.infraCreateFlags
	cmdInfraCreateAction := newInfraCreateAction(cmdInfraCreateFlags, azdContext, azCli, console, formatter, writer)
	cmdDeployFlags := flags.deployFlags
	cmdDeployAction, err := newDeployAction(cmdDeployFlags, azdContext, azCli, console, formatter, writer)
	if err != nil {
		return nil, err
	}
	cmdUpAction := newUpAction(cmdInitAction, cmdInfraCreateAction, cmdDeployAction, console)
	return cmdUpAction, nil
}

func initMonitorAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags monitorFlags, args []string) (actions.Action, error) {
	azdContext, err := newAzdContext()
	if err != nil {
		return nil, err
	}
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	console := newConsoleFromOptions(o, formatter, writer, cmd)
	commandRunner := newCommandRunnerFromConsole(console)
	manager := config.NewManager()
	authManager, err := auth.NewManager(writer, manager)
	if err != nil {
		return nil, err
	}
	tokenCredential, err := newCredential(authManager)
	if err != nil {
		return nil, err
	}
	azCli := newAzCliFromOptions(o, commandRunner, tokenCredential)
	cmdMonitorAction := newMonitorAction(azdContext, azCli, console, flags)
	return cmdMonitorAction, nil
}

func initRestoreAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags restoreFlags, args []string) (actions.Action, error) {
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	console := newConsoleFromOptions(o, formatter, writer, cmd)
	azdContext, err := newAzdContext()
	if err != nil {
		return nil, err
	}
	cmdRestoreAction := newRestoreAction(flags, console, azdContext)
	return cmdRestoreAction, nil
}

func initShowAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags showFlags, args []string) (actions.Action, error) {
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	console := newConsoleFromOptions(o, formatter, writer, cmd)
	azdContext, err := newAzdContext()
	if err != nil {
		return nil, err
	}
	cmdShowAction := newShowAction(console, formatter, writer, azdContext, flags)
	return cmdShowAction, nil
}

func initVersionAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags versionFlags, args []string) (actions.Action, error) {
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	console := newConsoleFromOptions(o, formatter, writer, cmd)
	cmdVersionAction := newVersionAction(flags, formatter, writer, console)
	return cmdVersionAction, nil
}

func initInfraCreateAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags infraCreateFlags, args []string) (actions.Action, error) {
	azdContext, err := newAzdContext()
	if err != nil {
		return nil, err
	}
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	console := newConsoleFromOptions(o, formatter, writer, cmd)
	commandRunner := newCommandRunnerFromConsole(console)
	manager := config.NewManager()
	authManager, err := auth.NewManager(writer, manager)
	if err != nil {
		return nil, err
	}
	tokenCredential, err := newCredential(authManager)
	if err != nil {
		return nil, err
	}
	azCli := newAzCliFromOptions(o, commandRunner, tokenCredential)
	cmdInfraCreateAction := newInfraCreateAction(flags, azdContext, azCli, console, formatter, writer)
	return cmdInfraCreateAction, nil
}

func initInfraDeleteAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags infraDeleteFlags, args []string) (actions.Action, error) {
	azdContext, err := newAzdContext()
	if err != nil {
		return nil, err
	}
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	console := newConsoleFromOptions(o, formatter, writer, cmd)
	commandRunner := newCommandRunnerFromConsole(console)
	manager := config.NewManager()
	authManager, err := auth.NewManager(writer, manager)
	if err != nil {
		return nil, err
	}
	tokenCredential, err := newCredential(authManager)
	if err != nil {
		return nil, err
	}
	azCli := newAzCliFromOptions(o, commandRunner, tokenCredential)
	cmdInfraDeleteAction := newInfraDeleteAction(flags, azdContext, azCli, console)
	return cmdInfraDeleteAction, nil
}

func initEnvSetAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags struct{}, args []string) (actions.Action, error) {
	azdContext, err := newAzdContext()
	if err != nil {
		return nil, err
	}
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	console := newConsoleFromOptions(o, formatter, writer, cmd)
	commandRunner := newCommandRunnerFromConsole(console)
	manager := config.NewManager()
	authManager, err := auth.NewManager(writer, manager)
	if err != nil {
		return nil, err
	}
	tokenCredential, err := newCredential(authManager)
	if err != nil {
		return nil, err
	}
	azCli := newAzCliFromOptions(o, commandRunner, tokenCredential)
	cmdEnvSetAction := newEnvSetAction(azdContext, azCli, console, o, args)
	return cmdEnvSetAction, nil
}

func initEnvSelectAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags struct{}, args []string) (actions.Action, error) {
	azdContext, err := newAzdContext()
	if err != nil {
		return nil, err
	}
	cmdEnvSelectAction := newEnvSelectAction(azdContext, args)
	return cmdEnvSelectAction, nil
}

func initEnvListAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags struct{}, args []string) (actions.Action, error) {
	azdContext, err := newAzdContext()
	if err != nil {
		return nil, err
	}
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	cmdEnvListAction := newEnvListAction(azdContext, formatter, writer)
	return cmdEnvListAction, nil
}

func initEnvNewAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags envNewFlags, args []string) (actions.Action, error) {
	azdContext, err := newAzdContext()
	if err != nil {
		return nil, err
	}
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	console := newConsoleFromOptions(o, formatter, writer, cmd)
	commandRunner := newCommandRunnerFromConsole(console)
	manager := config.NewManager()
	authManager, err := auth.NewManager(writer, manager)
	if err != nil {
		return nil, err
	}
	tokenCredential, err := newCredential(authManager)
	if err != nil {
		return nil, err
	}
	azCli := newAzCliFromOptions(o, commandRunner, tokenCredential)
	cmdEnvNewAction := newEnvNewAction(azdContext, azCli, flags, console)
	return cmdEnvNewAction, nil
}

func initEnvRefreshAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags struct{}, args []string) (actions.Action, error) {
	azdContext, err := newAzdContext()
	if err != nil {
		return nil, err
	}
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	console := newConsoleFromOptions(o, formatter, writer, cmd)
	commandRunner := newCommandRunnerFromConsole(console)
	manager := config.NewManager()
	authManager, err := auth.NewManager(writer, manager)
	if err != nil {
		return nil, err
	}
	tokenCredential, err := newCredential(authManager)
	if err != nil {
		return nil, err
	}
	azCli := newAzCliFromOptions(o, commandRunner, tokenCredential)
	cmdEnvRefreshAction := newEnvRefreshAction(azdContext, azCli, o, console, formatter, writer)
	return cmdEnvRefreshAction, nil
}

func initEnvGetValuesAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags struct{}, args []string) (actions.Action, error) {
	azdContext, err := newAzdContext()
	if err != nil {
		return nil, err
	}
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	console := newConsoleFromOptions(o, formatter, writer, cmd)
	commandRunner := newCommandRunnerFromConsole(console)
	manager := config.NewManager()
	authManager, err := auth.NewManager(writer, manager)
	if err != nil {
		return nil, err
	}
	tokenCredential, err := newCredential(authManager)
	if err != nil {
		return nil, err
	}
	azCli := newAzCliFromOptions(o, commandRunner, tokenCredential)
	cmdEnvGetValuesAction := newEnvGetValuesAction(azdContext, console, formatter, writer, azCli, o)
	return cmdEnvGetValuesAction, nil
}

func initPipelineConfigAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags pipelineConfigFlags, args []string) (actions.Action, error) {
	azdContext, err := newAzdContext()
	if err != nil {
		return nil, err
	}
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	console := newConsoleFromOptions(o, formatter, writer, cmd)
	cmdPipelineConfigAction := newPipelineConfigAction(azdContext, console, flags)
	return cmdPipelineConfigAction, nil
}

func initTemplatesListAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags templatesListFlags, args []string) (actions.Action, error) {
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	templateManager := templates.NewTemplateManager()
	cmdTemplatesListAction := newTemplatesListAction(flags, formatter, writer, templateManager)
	return cmdTemplatesListAction, nil
}

func initTemplatesShowAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags struct{}, args []string) (actions.Action, error) {
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	templateManager := templates.NewTemplateManager()
	cmdTemplatesShowAction := newTemplatesShowAction(formatter, writer, templateManager, args)
	return cmdTemplatesShowAction, nil
}

func initConfigListAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags struct{}, args []string) (actions.Action, error) {
	manager := config.NewManager()
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	cmdConfigListAction := newConfigListAction(manager, formatter, writer)
	return cmdConfigListAction, nil
}

func initConfigGetAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags struct{}, args []string) (actions.Action, error) {
	manager := config.NewManager()
	formatter, err := output.GetCommandFormatter(cmd)
	if err != nil {
		return nil, err
	}
	writer := newWriter(cmd)
	cmdConfigGetAction := newConfigGetAction(manager, formatter, writer, args)
	return cmdConfigGetAction, nil
}

func initConfigSetAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags struct{}, args []string) (actions.Action, error) {
	manager := config.NewManager()
	cmdConfigSetAction := newConfigSetAction(manager, args)
	return cmdConfigSetAction, nil
}

func initConfigUnsetAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags struct{}, args []string) (actions.Action, error) {
	manager := config.NewManager()
	cmdConfigUnsetAction := newConfigUnsetAction(manager, args)
	return cmdConfigUnsetAction, nil
}

func initConfigResetAction(cmd *cobra.Command, o *internal.GlobalCommandOptions, flags struct{}, args []string) (actions.Action, error) {
	manager := config.NewManager()
	cmdConfigResetAction := newConfigResetAction(manager, args)
	return cmdConfigResetAction, nil
}
