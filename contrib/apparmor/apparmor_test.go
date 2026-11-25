//go:build linux

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package apparmor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/pkg/testutil"
	"github.com/stretchr/testify/require"
)

func TestDumpDefaultProfile(t *testing.T) {
	if _, err := aaParser("--version"); err != nil {
		t.Skipf("apparmor_parser not available: %+v", err)
	}
	name := "test-dump-default-profile"
	prof, err := DumpDefaultProfile(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Generated profile %q", name)
	t.Log(prof)
}

func TestDefaultProfileSignals(t *testing.T) {
	testutil.RequiresRoot(t)
	stack, err := os.ReadFile("/sys/kernel/security/apparmor/features/domain/stack")
	if os.IsNotExist(err) {
		t.Skip("AppArmor stacking is not available")
	}
	require.NoError(t, err)
	if strings.TrimSpace(string(stack)) != "yes" {
		t.Skip("AppArmor stacking is not enabled")
	}
	if _, err := exec.LookPath("apparmor_parser"); err != nil {
		t.Skipf("apparmor_parser not available: %v", err)
	}
	aaExec, err := exec.LookPath("aa-exec")
	if err != nil {
		t.Skipf("aa-exec not available: %v", err)
	}

	f, err := os.CreateTemp(t.TempDir(), "containerd-test-signals-")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	name := filepath.Base(f.Name())
	profile, err := DumpDefaultProfile(name)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.Name(), []byte(profile), 0600))
	out, err := aaParser("-K", "-a", f.Name())
	require.NoError(t, err, "%s", out)
	t.Cleanup(func() {
		out, err := aaParser("-R", f.Name())
		require.NoError(t, err, "%s", out)
	})

	for _, label := range []string{name, name + "//&unconfined"} {
		t.Run(label, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			// Check the executing shell's label; a supported stack alone does not prove enforcement.
			const script = `
IFS= read -r label < /proc/self/attr/apparmor/current || exit 1
printf 'label=%s\n' "$label"
[ "$label" = "$1 (enforce)" ] || exit 1
delivered=no
trap 'delivered=yes' URG
kill -URG "$$" || exit 1
[ "$delivered" = yes ] || exit 1
printf 'SIGURG delivered\n'
`
			cmd := exec.CommandContext(ctx, aaExec, "-p", label, "--", "/bin/sh", "-c", script, "sh", label)
			out, err := cmd.CombinedOutput()
			t.Logf("%s", out)
			require.NoError(t, err)
		})
	}
}
