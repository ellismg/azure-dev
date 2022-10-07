package maven

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/azure/azure-dev/cli/azd/test/ostest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_getMavenPath(t *testing.T) {
	rootPath := os.TempDir()
	sourcePath := filepath.Join(rootPath, "src")
	projectPath := filepath.Join(sourcePath, "api")

	pathDir := os.TempDir()

	require.NoError(t, os.MkdirAll(projectPath, 0755))
	ostest.Unsetenv(t, "PATH")

	type args struct {
		projectPath     string
		rootProjectPath string
	}

	tests := []struct {
		name         string
		mvnwPath     []string
		mvnwRelative bool
		mvnPath      []string
		envVar       map[string]string
		want         string
		wantErr      bool
	}{
		{name: "MvnwProjectPath", mvnwPath: []string{projectPath}, want: filepath.Join(projectPath, mvnwWithExt())},
		{name: "MvnwSrcPath", mvnwPath: []string{sourcePath}, want: filepath.Join(sourcePath, mvnwWithExt())},
		{name: "MvnwRootPath", mvnwPath: []string{rootPath}, want: filepath.Join(rootPath, mvnwWithExt())},
		{name: "MvnwFirst", mvnwPath: []string{rootPath}, want: filepath.Join(rootPath, mvnwWithExt()),
			mvnPath: []string{pathDir}, envVar: map[string]string{"PATH": pathDir}},
		{name: "MvnwProjectPathRelative", mvnwPath: []string{projectPath}, want: filepath.Join(projectPath, mvnwWithExt()), mvnwRelative: true},
		{name: "MvnwSrcPathRelative", mvnwPath: []string{sourcePath}, want: filepath.Join(sourcePath, mvnwWithExt()), mvnwRelative: true},
		{name: "MvnwRootPathRelative", mvnwPath: []string{rootPath}, want: filepath.Join(rootPath, mvnwWithExt()), mvnwRelative: true},
		{name: "Mvn", mvnPath: []string{pathDir}, envVar: map[string]string{"PATH": pathDir}, want: filepath.Join(pathDir, mvnWithExt())},
		{name: "NotFound", want: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			placeExecutable(t, mvnwWithExt(), tt.mvnwPath...)
			placeExecutable(t, mvnWithExt(), tt.mvnPath...)
			ostest.Setenvs(t, tt.envVar)

			args := args{}
			if tt.mvnwRelative {
				ostest.Chdir(t, rootPath)
				// Set PWD directly to avoid symbolic links

				t.Setenv("PWD", rootPath)
				projectPathRel, err := filepath.Rel(rootPath, projectPath)
				require.NoError(t, err)
				args.projectPath = projectPathRel
				args.rootProjectPath = ""
			} else {
				args.projectPath = projectPath
				args.rootProjectPath = rootPath
			}

			wd, err := os.Getwd()
			require.NoError(t, err)
			log.Printf("rootPath: %s, cwd: %s, getMavenPath(%s, %s)\n", rootPath, wd, args.projectPath, args.rootProjectPath)
			actual, err := getMavenPath(args.projectPath, args.rootProjectPath)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.want, actual)
		})
	}
}

func placeExecutable(t *testing.T, name string, dirs ...string) {
	for _, createPath := range dirs {
		toCreate := filepath.Join(createPath, name)
		ostest.Create(t, toCreate)

		err := os.Chmod(toCreate, 0755)
		require.NoError(t, err)
	}
}

func mvnWithExt() string {
	if runtime.GOOS == "windows" {
		// For Windows, we want to test EXT resolution behavior
		return "mvn.cmd"
	} else {
		return "mvn"
	}
}

func mvnwWithExt() string {
	if runtime.GOOS == "windows" {
		// For Windows, we want to test EXT resolution behavior
		return "mvnw.cmd"
	} else {
		return "mvnw"
	}
}
