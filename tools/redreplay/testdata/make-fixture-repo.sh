#!/bin/sh
# make-fixture-repo.sh DIR
#
# Creates a Go repository in DIR (which must not exist or be empty) whose
# tags model the RED/GREEN histories redreplay has to judge:
#
#   base        Add is a stub that returns 0
#   good-red    base + TestAdd, which fails against the stub
#   good-green  good-red + a real Add; TestAdd passes
#   bad-green   good-red + an unrelated change; TestAdd still fails
#   pass-red    base + TestZero, which already passes against the stub
#
# git runs without user or system configuration so that the fixture does not
# depend on the machine it is built on.
set -eu

dir=${1:?usage: make-fixture-repo.sh DIR}

GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_NOSYSTEM=1
GIT_AUTHOR_NAME=Fixture
GIT_AUTHOR_EMAIL=fixture@example.com
GIT_AUTHOR_DATE=2026-01-01T00:00:00Z
GIT_COMMITTER_NAME=Fixture
GIT_COMMITTER_EMAIL=fixture@example.com
GIT_COMMITTER_DATE=2026-01-01T00:00:00Z
export GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM \
	GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_AUTHOR_DATE \
	GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL GIT_COMMITTER_DATE
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE

mkdir -p "$dir"
cd "$dir"
git init -q -b main

commit() {
	git add -A
	git commit -q --no-verify -m "$1"
	git tag "$2"
}

cat >go.mod <<'EOF'
module example.com/fixture

go 1.27
EOF
cat >calc.go <<'EOF'
package calc

// Add returns the sum of a and b.
func Add(a, b int) int { return 0 }
EOF
commit "chore: stub Add" base

cat >calc_test.go <<'EOF'
package calc

import "testing"

func TestAdd(t *testing.T) {
	if got := Add(2, 3); got != 5 {
		t.Fatalf("Add(2, 3) = %d, want 5", got)
	}
}
EOF
commit "test: add failing TestAdd" good-red

cat >README <<'EOF'
calc fixture
EOF
commit "docs: add README" bad-green

git checkout -q good-red
cat >calc.go <<'EOF'
package calc

// Add returns the sum of a and b.
func Add(a, b int) int { return a + b }
EOF
commit "feat: implement Add" good-green

git checkout -q base
cat >calc_test.go <<'EOF'
package calc

import "testing"

func TestZero(t *testing.T) {
	if got := Add(0, 0); got != 0 {
		t.Fatalf("Add(0, 0) = %d, want 0", got)
	}
}
EOF
commit "test: add TestZero" pass-red

git checkout -q main
