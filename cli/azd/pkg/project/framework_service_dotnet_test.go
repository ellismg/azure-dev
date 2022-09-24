// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package project

import (
	"context"
	"strings"
	"testing"

	"github.com/azure/azure-dev/cli/azd/pkg/environment"
	"github.com/azure/azure-dev/cli/azd/pkg/exec"
	"github.com/azure/azure-dev/cli/azd/pkg/infra/provisioning"
	"github.com/azure/azure-dev/cli/azd/test/mocks"
	"github.com/stretchr/testify/require"
)

func TestBicepOutputsWithDoubleUnderscoresAreConverted(t *testing.T) {
	mockContext := mocks.NewMockContext(context.Background())

	// keys that we saw when running.
	keys := []string{}

	mockContext.CommandRunner.When(func(args exec.RunArgs, command string) bool {
		return strings.Contains(command, "dotnet user-secrets set")
	}).RespondFn(func(args exec.RunArgs) (exec.RunResult, error) {
		t.Logf("dotnet user-secrets set was called with: %+v", args)
		keys = append(keys, args.Args[2])
		return exec.NewRunResult(0, "", ""), nil
	})

	// Create an new NewDotNetProject and downcast it from the FrameworkService interface
	// to the concrete type, so we can call `setUserSecretsFromOutputs`.
	dp := NewDotNetProject(*mockContext.Context, &ServiceConfig{
		// We don't care about any of this data really, it just needs to be here
		// so things don't crash.
		Project: &ProjectConfig{
			Path: "/sample/path/for/test",
		},
		RelativePath: "",
	}, environment.Ephemeral()).(*dotnetProject)

	err := dp.setUserSecretsFromOutputs(*mockContext.Context, ServiceLifecycleEventArgs{
		Args: map[string]any{
			// this corresponds to a bicep file that had two outputs:
			// output EXAMPLE_OUTPUT string = "foo"
			// output EXAMPLE__NESTED__OUTPUT string = "bar"
			"bicepOutput": map[string]provisioning.OutputParameter{
				"EXAMPLE_OUTPUT":          {Type: "string", Value: "foo"},
				"EXAMPLE__NESTED__OUTPUT": {Type: "string", Value: "bar"},
			},
		},
	})

	require.NoError(t, err)
	require.Len(t, keys, 2)

	// TODO: Sort `keys` and then ensure the values match "EXAMPLE_OUTPUT" and `EXAMPLE:NESTED:OUTPUT`
}
