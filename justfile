# Achilles — task runner
# Run `just` with no args to see available recipes.

set dotenv-load := false

bin_dir := "bin"

# ─── Default ──────────────────────────────────────────────

# List available recipes
default:
    @just --list

# ─── Build ────────────────────────────────────────────────

# Build the achilles CLI
build:
    @mkdir -p {{ bin_dir }}
    go build -o {{ bin_dir }}/achilles .

# ─── Test ─────────────────────────────────────────────────

# Run all Go tests
test:
    go test ./...

# Run all Go tests with race detector
test-race:
    go test -race ./...

# Run all Go tests with verbose output
test-v:
    go test -v ./...

# ─── Lint ─────────────────────────────────────────────────

# Run go vet
vet:
    go vet ./...

# ─── Clean ────────────────────────────────────────────────

# Remove build artifacts
clean:
    rm -rf {{ bin_dir }}
