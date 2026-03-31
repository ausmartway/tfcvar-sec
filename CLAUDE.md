# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
go build -o tfcvar-sec .

# Build with version info injected (as goreleaser does)
go build -ldflags "-X version.Version=dev -X version.PackageManager=manual" -o tfcvar-sec .

# Run directly
go run . scan --token <TOKEN> --hostname <HOSTNAME>

# Run tests
go test ./...

# Run a single test
go test ./cmd/... -run TestName -v

# Lint
golangci-lint run ./...

# Release (uses goreleaser)
goreleaser release --snapshot --clean
```

## Architecture

The tool is a single-command CLI (`scan`) built with Cobra + Viper:

- **`main.go`** — entry point, calls `cmd.Execute()`
- **`cmd/root.go`** — defines the root `tfcvar-sec` command with `--version` flag
- **`cmd/scan.go`** — all scan logic lives here: flag definitions, credential resolution, TFC API traversal, and output
- **`version/`** — package that holds version string, injected at build time via `-ldflags`

### Scan logic flow (`cmd/scan.go`)

1. `initConfig()` resolves the TFE token in priority order: CLI flag → `TFE_TOKEN` env var → `~/.terraform.d/credentials.tfrc.json`
2. `scan()` uses `hashicorp/go-tfe` client to walk: orgs → workspaces (paginated) → variables per workspace
3. Each variable is checked against two lists:
   - `sensitiveEnvVariables` map — exact-match env var names known to hold provider secrets (Red/Critical)
   - `sensitiveTfcVariablePattens` slice — substrings matched case-insensitively against terraform variable names and `TF_VAR_*` env vars (Yellow/Warning)
4. With `--fixcritical` / `--fixwarning`, flagged vars are updated in-place via `client.Variables.Update(..., Sensitive: true)`

### Variable Sets

Variable set variables are scanned at the org level after workspace variables. Each org's variable sets are paginated via `client.VariableSets.List()`, and each set's variables via `client.VariableSetVariables.List()`. Findings are reported as `variable set: <name>` rather than `workspace: <name>`. The same `--fixcritical`/`--fixwarning` flags apply.

### Adding new providers

To add coverage for a new Terraform provider:
- **Env var secrets**: add entries to the `sensitiveEnvVariables` map in `cmd/scan.go`
- **Terraform variable name patterns**: add substrings to `sensitiveTfcVariablePattens` — include a comment with a link to the provider's credential docs
