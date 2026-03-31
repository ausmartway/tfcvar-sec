# Variable Set Support Design

**Date:** 2026-03-31
**Branch:** var-set

## Problem

`tfcvar-sec scan` currently only checks workspace-level variables. Terraform Cloud/Enterprise also supports **Variable Sets** — org-level collections of variables that can be applied globally (all workspaces) or scoped to specific workspaces. Credentials stored in variable sets but not marked sensitive are invisible to the current scan.

## Goals

- Scan all variable sets in each organization (global and scoped)
- Apply the same Critical/Warning detection logic as workspace variables
- Support auto-fix via `--fixcritical` / `--fixwarning`
- Report findings at the variable set level (not per workspace), since fixing a variable set variable is a single operation regardless of how many workspaces it applies to

## Out of Scope

- Deduplication between workspace variables and variable set variables (a variable could exist in both places with the same name — each is reported independently)
- Filtering by which workspaces a variable set is applied to

## Approach

Option A: List variable sets per org, then list their variables separately.

- `client.VariableSets.List(ctx, org.Name, ...)` — paginated, page size 50
- For each variable set: `client.VariableSetVariables.List(ctx, variableSetID, ...)` — page size 1000
- Requires `go mod vendor` to sync vendor directory from `go-tfe v0.19.0` → `v1.17.0`

## Data Model Changes

### `varVialation` struct

Add three fields:

```go
type varVialation struct {
    orgName         string
    workspaceName   string  // empty for variable set findings
    variableSetName string  // empty for workspace findings; new
    category        string
    varName         string
    variableSetID   string  // for fix calls only; new
    varID           string  // for fix calls only; new
}
```

`variableSetID` and `varID` are internal — never printed, only used for `VariableSetVariables.Update` fix calls.

### New counters

```go
var numVarSet, numVarSetVar int
```

Added to the final summary:

```
Total number of Variable Sets scanned: N
Total number of Variable Set Variables scanned: N
```

## Scan Flow

```
for each org:
  [existing] paginate workspaces → variables → detect → optionally fix

  [new] paginate variable sets (page 50)
    for each variable set:
      list all variables (page 1000)
      numVarSet++
      numVarSetVar += len(variables)
      for each variable:
        apply same Critical/Warning logic as workspace variables
        append varVialation{variableSetName: vs.Name, variableSetID: vs.ID, varID: v.ID, ...}
        if --fixcritical/--fixwarning: client.VariableSetVariables.Update(ctx, vs.ID, v.ID, Sensitive: true)
```

## Output Format

Existing workspace output (unchanged):
```
Organisation: myorg, workspace: ws-prod, category: env, Variable: AWS_SECRET_ACCESS_KEY
```

New variable set output:
```
Organisation: myorg, variable set: prod-creds, category: env, Variable: AWS_SECRET_ACCESS_KEY
```

The output loop branches on `variableSetName != ""` to pick the right label. Red/Yellow coloring rules are identical to workspace variables.

## Fix Behaviour

`--fixcritical` and `--fixwarning` apply to both workspace variables (existing) and variable set variables (new). Fix calls use `client.VariableSetVariables.Update(ctx, variableSetID, varID, tfe.VariableSetVariableUpdateOptions{Sensitive: tfe.Bool(true)})`.

Fix counters (`numCriticalFix`, `numWarningFix`) are shared — the summary line reports total fixes across both workspace and variable set findings.

## Prerequisites

The vendor directory must be updated before compilation:

```bash
go mod vendor
```

This syncs from `go-tfe v0.19.0` (current vendor) to `v1.17.0` (required in `go.mod`), which adds `variable_set.go` and `variable_set_variable.go` to the vendored package.
