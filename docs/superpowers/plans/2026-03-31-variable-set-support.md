# Variable Set Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `tfcvar-sec scan` to also detect (and optionally fix) unsensitive variables inside Terraform Cloud variable sets, reporting findings at the variable set level.

**Architecture:** All changes are in `cmd/scan.go`. The `varVialation` struct gains three fields for variable set context. After the existing workspace loop, a new variable set loop iterates `VariableSets.List` then `VariableSetVariables.List` per set, applying identical detection logic. Detection functions are extracted into testable helpers.

**Tech Stack:** Go, `github.com/hashicorp/go-tfe v1.17.0`, Cobra, no test framework (stdlib `testing`)

---

### Task 1: Sync vendor directory

**Files:**
- Modify: `vendor/` (via `go mod vendor`)

The vendor directory has `go-tfe v0.19.0` but `go.mod` requires `v1.17.0` which adds `variable_set.go` and `variable_set_variable.go`. The current branch won't compile until this is fixed.

- [ ] **Step 1: Sync vendor**

```bash
go mod vendor
```

- [ ] **Step 2: Verify the new files are present**

```bash
ls vendor/github.com/hashicorp/go-tfe/variable_set*.go
```

Expected output:
```
vendor/github.com/hashicorp/go-tfe/variable_set.go
vendor/github.com/hashicorp/go-tfe/variable_set_variable.go
```

- [ ] **Step 3: Verify the project builds (ignore the stub compile errors for now — they will be fixed in Task 3)**

The broken stub will cause compile errors (`currentPage` undeclared, `vsl` declared but not used). That's expected and will be resolved in Task 3.

- [ ] **Step 4: Commit the vendor sync**

```bash
git add vendor/ go.sum
git commit -m "chore: sync vendor to go-tfe v1.17.0"
```

---

### Task 2: Extract detection helpers and write unit tests

**Files:**
- Modify: `cmd/scan.go` — extract two helper functions
- Create: `cmd/scan_test.go` — unit tests for detection logic

The detection logic is currently inline in the scan loop. Extracting it enables unit testing and will be reused for variable set variables.

- [ ] **Step 1: Create `cmd/scan_test.go` with failing tests**

```go
package cmd

import (
	"testing"
)

func TestIsEnvVarCritical(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		{"AWS_SECRET_ACCESS_KEY", true},
		{"VAULT_TOKEN", true},
		{"GITHUB_TOKEN", true},
		{"AWS_ACCESS_KEY_ID", false}, // not in the sensitive list
		{"AWS_REGION", false},
		{"TF_VAR_my_password", false}, // TF_VAR_ prefix handled separately
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := isEnvVarCritical(tt.key)
			if got != tt.expected {
				t.Errorf("isEnvVarCritical(%q) = %v, want %v", tt.key, got, tt.expected)
			}
		})
	}
}

func TestIsTfVarWarning(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		{"aws_secret_key", true},
		{"db_password", true},
		{"api_token", true},
		{"AWS_SECRET_KEY", true},  // case-insensitive
		{"region", false},
		{"environment", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := isTfVarWarning(tt.key)
			if got != tt.expected {
				t.Errorf("isTfVarWarning(%q) = %v, want %v", tt.key, got, tt.expected)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests — expect compile failure (functions not defined yet)**

```bash
go test ./cmd/... -run TestIsEnvVarCritical -v 2>&1 | head -20
```

Expected: compile error mentioning `isEnvVarCritical` undefined.

- [ ] **Step 3: Add the two helper functions to `cmd/scan.go`**

Add these two functions after the `contains()` function (around line 248):

```go
// isEnvVarCritical returns true if the env var key is a known provider secret
// that should always be marked sensitive.
func isEnvVarCritical(key string) bool {
	return sensitiveEnvVariables[key]
}

// isTfVarWarning returns true if the terraform variable name contains a pattern
// that suggests it may hold a secret.
func isTfVarWarning(key string) bool {
	return contains(strings.ToLower(key), sensitiveTfcVariablePattens)
}
```

- [ ] **Step 4: Run tests — expect pass**

```bash
go test ./cmd/... -run "TestIsEnvVarCritical|TestIsTfVarWarning" -v
```

Expected output:
```
--- PASS: TestIsEnvVarCritical/AWS_SECRET_ACCESS_KEY (0.00s)
--- PASS: TestIsEnvVarCritical/VAULT_TOKEN (0.00s)
...
--- PASS: TestIsTfVarWarning/aws_secret_key (0.00s)
...
PASS
```

- [ ] **Step 5: Commit**

```bash
git add cmd/scan.go cmd/scan_test.go
git commit -m "test: extract and unit-test variable detection helpers"
```

---

### Task 3: Update varVialation struct and remove broken stub

**Files:**
- Modify: `cmd/scan.go`

Add the three new fields to `varVialation`, update the workspace violation constructor call to remain compatible, and remove the broken stub code that prevents compilation.

- [ ] **Step 1: Replace the `varVialation` struct definition (around line 224)**

Old:
```go
//flat structure
type varVialation struct {
	orgName       string
	workspaceName string
	category      string
	varName       string
}
```

New:
```go
// varVialation holds details of a single detected insecure variable.
// For workspace variables, workspaceName is set and variableSetName is empty.
// For variable set variables, variableSetName and variableSetID are set.
type varVialation struct {
	orgName         string
	workspaceName   string
	variableSetName string // set for variable set findings; empty for workspace findings
	variableSetID   string // used for fix calls only
	varID           string // used for fix calls only
	category        string
	varName         string
}
```

- [ ] **Step 2: Add a variable set violation constructor after `newVarVialation`**

After the existing `newVarVialation` function, add:

```go
func newVarSetVialation(orgName, variableSetName, variableSetID, varID, category, varName string) *varVialation {
	return &varVialation{
		orgName:         orgName,
		variableSetName: variableSetName,
		variableSetID:   variableSetID,
		varID:           varID,
		category:        category,
		varName:         varName,
	}
}
```

- [ ] **Step 3: Remove the broken stub code**

In `cmd/scan.go`, inside `scan()`, find and remove these lines (they appear just before `//for each org, get first page of workspaces`):

```go
		// for each org, get all variable set
		currentPage = 0
		vsl, err := client.VariableSets.List(ctx, org.Name, tfe.VariableSetListOptions{
			ListOptions: tfe.ListOptions{
				PageNumber: currentPage,
				PageSize:	50,
			},
			}
		)
		// for each variable set, get all variables

```

- [ ] **Step 4: Verify the project now compiles cleanly**

```bash
go build -o /dev/null .
```

Expected: no output (success).

- [ ] **Step 5: Run existing tests**

```bash
go test ./cmd/... -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add cmd/scan.go
git commit -m "refactor: update varVialation struct and remove broken var-set stub"
```

---

### Task 4: Add variable set scan loop and counters

**Files:**
- Modify: `cmd/scan.go`

Add two new counters and the variable set scan loop. The loop goes inside `for _, org := range orgs.Items`, after the workspace `for currentPage <= totalPage` loop closes.

- [ ] **Step 1: Add two new counters at the top of the var block (around line 37)**

Find:
```go
var numOrg, numWorkspace, numVar, numCritical, numWarning, numCriticalFix, numWarningFix int
```

Replace with:
```go
var numOrg, numWorkspace, numVar, numCritical, numWarning, numCriticalFix, numWarningFix int
var numVarSet, numVarSetVar int
```

- [ ] **Step 2: Add the variable set scan loop**

Inside `scan()`, after the workspace loop closes (after `currentPage = currentPage + 1` and the closing `}` of `for currentPage <= totalPage`), and still inside `for _, org := range orgs.Items`, add:

```go
			// Scan variable sets for this org
			vsPage := 1
			vsTotalPage := 1
			for vsPage <= vsTotalPage {
				vsl, err := client.VariableSets.List(ctx, org.Name, &tfe.VariableSetListOptions{
					ListOptions: tfe.ListOptions{
						PageNumber: vsPage,
						PageSize:   50,
					},
				})
				if err != nil {
					log.Fatal(err)
				}
				numVarSet = numVarSet + len(vsl.Items)
				for _, vs := range vsl.Items {
					vsVars, err := client.VariableSetVariables.List(ctx, vs.ID, &tfe.VariableSetVariableListOptions{
						ListOptions: tfe.ListOptions{
							PageNumber: 1,
							PageSize:   1000,
						},
					})
					if err != nil {
						log.Fatal(err)
					}
					numVarSetVar = numVarSetVar + len(vsVars.Items)
					for _, vsVar := range vsVars.Items {
						switch string(vsVar.Category) {
						case "env":
							if isEnvVarCritical(vsVar.Key) && !vsVar.Sensitive {
								numCritical = numCritical + 1
								varVialations = append(varVialations, *newVarSetVialation(org.Name, vs.Name, vs.ID, vsVar.ID, string(vsVar.Category), vsVar.Key))
								if fixCritical {
									numCriticalFix = numCriticalFix + 1
									_, updateErr := client.VariableSetVariables.Update(ctx, vs.ID, vsVar.ID, &tfe.VariableSetVariableUpdateOptions{
										Sensitive: tfe.Bool(true),
									})
									if updateErr != nil {
										fmt.Println(updateErr)
									}
								}
							} else if !vsVar.Sensitive && strings.Index(vsVar.Key, "TF_VAR_") == 0 {
								tt := strings.Replace(vsVar.Key, "TF_VAR_", "", 1)
								if isTfVarWarning(tt) {
									numWarning = numWarning + 1
									varVialations = append(varVialations, *newVarSetVialation(org.Name, vs.Name, vs.ID, vsVar.ID, string(vsVar.Category), vsVar.Key))
									if fixWarning {
										numWarningFix = numWarningFix + 1
										_, updateErr := client.VariableSetVariables.Update(ctx, vs.ID, vsVar.ID, &tfe.VariableSetVariableUpdateOptions{
											Sensitive: tfe.Bool(true),
										})
										if updateErr != nil {
											fmt.Println(updateErr)
										}
									}
								}
							}
						case "terraform":
							if !vsVar.Sensitive && isTfVarWarning(vsVar.Key) {
								numWarning = numWarning + 1
								varVialations = append(varVialations, *newVarSetVialation(org.Name, vs.Name, vs.ID, vsVar.ID, string(vsVar.Category), vsVar.Key))
								if fixWarning {
									numWarningFix = numWarningFix + 1
									_, updateErr := client.VariableSetVariables.Update(ctx, vs.ID, vsVar.ID, &tfe.VariableSetVariableUpdateOptions{
										Sensitive: tfe.Bool(true),
									})
									if updateErr != nil {
										fmt.Println(updateErr)
									}
								}
							}
						}
					}
				}
				vsTotalPage = vsl.TotalPages
				vsPage = vsPage + 1
			}
```

- [ ] **Step 3: Also refactor the workspace scan to use the extracted helpers**

In the workspace variable loop (inside `for _, wsVar := range variables.Items`), replace:

```go
						if sensitiveEnvVariables[wsVar.Key] && !wsVar.Sensitive {
```
with:
```go
						if isEnvVarCritical(wsVar.Key) && !wsVar.Sensitive {
```

And replace:
```go
								if contains(strings.ToLower(tt), sensitiveTfcVariablePattens) {
```
with:
```go
								if isTfVarWarning(tt) {
```

And replace:
```go
								if !wsVar.Sensitive && contains(strings.ToLower(wsVar.Key), sensitiveTfcVariablePattens) {
```
with:
```go
								if !wsVar.Sensitive && isTfVarWarning(wsVar.Key) {
```

- [ ] **Step 4: Verify build**

```bash
go build -o /dev/null .
```

Expected: no output.

- [ ] **Step 5: Run tests**

```bash
go test ./cmd/... -v
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add cmd/scan.go
git commit -m "feat: add variable set scan loop with critical/warning detection and auto-fix"
```

---

### Task 5: Update output loop and summary counters

**Files:**
- Modify: `cmd/scan.go`

Update the output loop to print `variable set:` instead of `workspace:` for variable set findings, and add the two new counter lines to the summary.

- [ ] **Step 1: Update the output loop**

Find the output loop (around line 410):

```go
		for i := 0; i < len(varVialations); i++ {
			var cc string
			if varVialations[i].category == "terraform" {
				cc = color.Yellow
			} else if strings.HasPrefix(varVialations[i].varName, "TF_VAR_") {
				cc = color.Yellow
			} else {
				cc = color.Red
			}
			fmt.Println("Orgnization:", varVialations[i].orgName, ",workspace:", varVialations[i].workspaceName, ",category:", varVialations[i].category, ",Variable:", cc+varVialations[i].varName+color.Reset)
		}
```

Replace with:

```go
		for i := 0; i < len(varVialations); i++ {
			var cc string
			if varVialations[i].category == "terraform" {
				cc = color.Yellow
			} else if strings.HasPrefix(varVialations[i].varName, "TF_VAR_") {
				cc = color.Yellow
			} else {
				cc = color.Red
			}
			if varVialations[i].variableSetName != "" {
				fmt.Println("Orgnization:", varVialations[i].orgName, ",variable set:", varVialations[i].variableSetName, ",category:", varVialations[i].category, ",Variable:", cc+varVialations[i].varName+color.Reset)
			} else {
				fmt.Println("Orgnization:", varVialations[i].orgName, ",workspace:", varVialations[i].workspaceName, ",category:", varVialations[i].category, ",Variable:", cc+varVialations[i].varName+color.Reset)
			}
		}
```

- [ ] **Step 2: Add variable set counter lines to summary**

Find:
```go
		fmt.Printf("Total number of Orgnisations scanned: %d\n", numOrg)
		fmt.Printf("Total number of Workspaces scanned: %d\n", numWorkspace)
		fmt.Printf("Total number of Variables scanned: %d\n", numVar)
```

Replace with:
```go
		fmt.Printf("Total number of Orgnisations scanned: %d\n", numOrg)
		fmt.Printf("Total number of Workspaces scanned: %d\n", numWorkspace)
		fmt.Printf("Total number of Variables scanned: %d\n", numVar)
		fmt.Printf("Total number of Variable Sets scanned: %d\n", numVarSet)
		fmt.Printf("Total number of Variable Set Variables scanned: %d\n", numVarSetVar)
```

- [ ] **Step 3: Verify build**

```bash
go build -o /dev/null .
```

Expected: no output.

- [ ] **Step 4: Run all tests**

```bash
go test ./cmd/... -v
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add cmd/scan.go
git commit -m "feat: update output and summary to include variable set findings"
```

---

### Task 6: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update the build command note and architecture section**

In `CLAUDE.md`, update the architecture section under "Active development (`var-set` branch)" to reflect that the implementation is now complete:

Find:
```
### Active development (`var-set` branch)

Variable Sets support is being added. The intent is to also scan variables attached to variable sets (org-level), not just workspace-level variables. The in-progress code calls `client.VariableSets.List()` per org and needs follow-on logic to iterate each set's variables via `client.VariableSetVariables.List()`.
```

Replace with:
```
### Variable Sets

Variable set variables are scanned at the org level after workspace variables. Each org's variable sets are paginated via `client.VariableSets.List()`, and each set's variables via `client.VariableSetVariables.List()`. Findings are reported as `variable set: <name>` rather than `workspace: <name>`. The same `--fixcritical`/`--fixwarning` flags apply.
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md to reflect completed variable set support"
```
