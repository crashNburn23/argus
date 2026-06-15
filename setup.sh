#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

INSTALL_DEV=true
RUN_TESTS=true
RUN_LINT=false
SKIP_SYNC=false

usage() {
    cat <<'EOF'
Usage: ./setup.sh [options]

Prepare Argus for local use.

Options:
  --runtime-only  Install runtime dependencies without development tools.
  --skip-tests    Do not run the test suite after setup.
  --lint          Run Ruff after the test suite.
  --skip-sync     Skip dependency installation; prepare and verify the existing environment.
  -h, --help      Show this help.

The script is idempotent. Existing .env files and user configuration are preserved.
EOF
}

log() {
    printf '\n==> %s\n' "$*"
}

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

for arg in "$@"; do
    case "$arg" in
        --runtime-only)
            INSTALL_DEV=false
            RUN_TESTS=false
            ;;
        --skip-tests)
            RUN_TESTS=false
            ;;
        --lint)
            RUN_LINT=true
            ;;
        --skip-sync)
            SKIP_SYNC=true
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Unknown option: $arg. Run ./setup.sh --help for usage."
            ;;
    esac
done

if [[ "$INSTALL_DEV" == false && "$RUN_LINT" == true ]]; then
    die "--lint requires development dependencies; remove --runtime-only."
fi

if command -v uv >/dev/null 2>&1; then
    UV="$(command -v uv)"
elif [[ -x "$HOME/.local/bin/uv" ]]; then
    UV="$HOME/.local/bin/uv"
else
    die "uv is required. Install it from https://docs.astral.sh/uv/ and rerun setup."
fi

log "Using $("$UV" --version)"

if [[ "$SKIP_SYNC" == false ]]; then
    log "Creating the virtual environment and installing dependencies"
    if [[ "$INSTALL_DEV" == true ]]; then
        "$UV" sync --extra dev
    else
        "$UV" sync
    fi
elif [[ ! -x ".venv/bin/python" ]]; then
    die "--skip-sync requires an existing .venv. Run ./setup.sh first."
fi

if [[ ! -f ".env" ]]; then
    log "Creating .env from .env.example"
    cp .env.example .env
    chmod 600 .env
else
    log "Preserving existing .env"
fi

log "Preparing runtime directories"
mkdir -p .cache/argus .data reports

log "Initializing the SQLite database"
".venv/bin/python" -c \
    "from argus.storage.database import _get_engine; _get_engine()"

log "Verifying the CLI"
".venv/bin/argus" --help >/dev/null

if [[ "$RUN_TESTS" == true ]]; then
    log "Running tests"
    ".venv/bin/pytest" -q
fi

if [[ "$RUN_LINT" == true ]]; then
    log "Running Ruff"
    ".venv/bin/ruff" check src tests
fi

cat <<'EOF'

Setup complete.

Next steps:
  1. Edit .env with your provider and threat-feed credentials.
  2. Check configuration and source health with: uv run argus doctor
  3. Select or inspect the model with: uv run argus model
  4. Run a command such as: uv run argus vuln cve CVE-2021-44228

Activate the environment for direct `argus` usage:
  source .venv/bin/activate
EOF
