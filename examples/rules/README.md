# Opt-in rule examples

The built-in rule set is empty. Nothing in this directory loads automatically; each file is a JSON array of rules you copy into a rules file.

## migration-prod-safe.json

Asks whether a migration described as safe was run against a copy of prod data.

Enable it by merging its object into a rules file:

- user-wide: `rules.json` in the Honest Jev config dir. Claude Code uses `userConfigDir()`, usually `~/.config/jev/rules.json`. omp uses `PI_CODING_AGENT_DIR/jev/rules.json` when `PI_CODING_AGENT_DIR` is set, else `$XDG_CONFIG_HOME/jev/rules.json` or `~/.config/jev/rules.json`.
- one repo: `.jev/rules.json` in that repo.
- or add it through the command. Claude Code: `honest-jev rule add "describing a database migration as safe" -> "Was it run against a copy of prod data?" evidence: "the command and its output"`. omp: `/honest-jev rule add …` with the same arguments. The id is derived from the `when` text, so it will not be `migration-prod-safe`.

Disable a rule in a later layer with `{"id": "<id>", "disabled": true}`.

## Re-adding pr-gstack-reviewed

The built-in `pr-gstack-reviewed` rule was removed from the defaults. To keep it, add it yourself.

Claude Code:

```
honest-jev rule add "presenting a pull request as ready to merge or calling it reviewed/clean/mergeable" -> "Has a real gstack /review run on THIS PR and is it clean?" evidence: "review record or Automated Code Review comment on this PR number with a CLEAN verdict and 0 unresolved threads; Auto-review bot comments, Devin checks, reviews on other PRs, or a self-review do not count"
```

omp: the same arguments with `/honest-jev rule add …`.

## omp coverage limits

Plain-text commands (`honest-jev strict`, `honest-jev rule list`, `stop honest-jev`) run through the omp `input` event, which covers interactive and RPC input. Print-mode (`-p`) and ACP input do not pass through that event; use the `/honest-jev` command where the session supports it.
