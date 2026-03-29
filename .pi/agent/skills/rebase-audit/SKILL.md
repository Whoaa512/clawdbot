# Rebase Audit Skill

Assess whether rebasing on an upstream branch is worthwhile by analyzing new commits, conflict risk, and security/supply-chain impact.

## Trigger

User asks about upstream changes, whether to rebase, or wants a rebase audit.

## Workflow

### 1. Fetch & Summarize

```bash
git fetch upstream --quiet
git log --oneline HEAD..upstream/main --no-merges | head -30
git log --oneline HEAD..upstream/main --no-merges | wc -l
```

Categorize commits by area (infra, security, platform, deps, CI, docs). Highlight user-facing and security-relevant changes.

### 2. Conflict Risk Assessment

Find files touched by both branches:

```bash
git diff --name-only HEAD..HEAD~N | sort > /tmp/local-files.txt   # N = local commit count
git diff --name-only HEAD...upstream/main | sort > /tmp/upstream-files.txt
comm -12 /tmp/local-files.txt /tmp/upstream-files.txt
```

Rate conflict risk: Low / Medium / High based on overlap count and file sensitivity.

### 3. Security Audit

Filter security-relevant commits:

```bash
git log --oneline HEAD..upstream/main --no-merges | rg -i 'secur|allow|auth|pair|harden|fail.close|trust|token|cred|permiss|sandbox|escape|replay|injection'
```

For each hit, read the diff and classify:
- 🔴 **High**: sandbox escapes, auth bypasses, privilege escalation, injection fixes
- 🟡 **Medium**: auth flow refactors, hardening without known exploit
- 🟢 **Low**: docs-only, test-only, defense-in-depth

### 4. Supply Chain Audit

Check dependency and build pipeline changes:

```bash
git diff HEAD...upstream/main -- package.json | head -80
git diff --stat HEAD...upstream/main -- pnpm-lock.yaml
git log --oneline HEAD..upstream/main --no-merges -- package.json pnpm-lock.yaml
git diff HEAD...upstream/main -- Dockerfile docker-setup.sh .github/workflows/
```

Flag:
- New dependencies (especially post-install scripts)
- Removed or replaced dependencies
- Lock file churn disproportionate to package.json changes
- CI workflow changes (new actions, permission changes, secret refs)
- Dockerfile base image or install changes
- New patches in `pnpm.patchedDependencies`

### 5. Verdict

Output a structured report:

```
## Conflict Risk: [Low/Medium/High]
- N files overlap, list them
- Note which are likely to conflict

## Security Fixes (ranked by severity)
- 🔴 High: ...
- 🟡 Medium: ...
- 🟢 Low: ...

## Supply Chain Changes
- New deps: [none | list]
- Removed deps: [none | list]
- Lock file: [net +/- lines, single commit or many]
- CI: [changes summary]
- Docker: [changes summary]

## Verdict: [Rebase recommended / Skip / Defer]
[One-line rationale]
```

## Notes

- Adapt `upstream/main` to whatever the user's upstream remote/branch is.
- If the local branch has no unique commits (fast-forward), just say so.
- For large diffs (100+ commits), focus the security audit on files matching the filter patterns rather than reading every diff.
