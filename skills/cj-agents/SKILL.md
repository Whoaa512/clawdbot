---
name: cj-agents
description: Spawn CJ's custom Claude Code agents for specialized tasks. Use when the user asks to run a specific agent like code-critic, grug-architect, jared-biz-strategist, etc.
metadata: {"clawdbot":{"emoji":"🤖","requires":{"anyBins":["claude"]}}}
---

# CJ's Custom Claude Code Agents

Spawn specialized Claude Code agents for different tasks. These are CJ's personal agent library.

## Available Agents

| Agent | Use For | Model |
|-------|---------|-------|
| `beads-tracker` | Issue tracking with bd CLI | sonnet |
| `code-critic` | Ruthless code review, complexity audits | opus |
| `deep-research` | Deep topic exploration and synthesis | inherit |
| `game-asset-prompter` | Game sprite/tile prompt generation | sonnet |
| `game-designer` | Game mechanics and design | opus |
| `grug-architect` | Simple, pragmatic system architecture | opus |
| `image-prompter` | AI image generation prompts | sonnet |
| `ios-fiction-finder` | iOS QA testing and bug finding | opus |
| `jared-biz-strategist` | Business strategy and analysis | opus |
| `product-owner` | Feature/scope definition, PRDs | opus |
| `super-coder` | Complex code implementation | opus |
| `tinyprd` | PRD creation optimized for LLMs | opus |

## How to Spawn

### One-shot (non-interactive, returns result)
```bash
# Use --print for one-shot execution
claude --model <model> --agent <agent-name> --print "<task>"

# Examples:
claude --model opus --agent code-critic --print "Review this PR for over-engineering"
claude --model opus --agent jared-biz-strategist --print "Analyze pricing strategy for X"
claude --model opus --agent grug-architect --print "Design a simple notification system"
```

### Background (for longer tasks)
```bash
# Start in background
bash workdir:/tmp background:true command:"claude --model opus --agent <agent-name> --print \"<task>\""

# Monitor progress
process action:log sessionId:<id>
process action:poll sessionId:<id>
```

### Interactive (via tmux)
For interactive sessions where you need back-and-forth, use tmux:
```bash
SOCKET="${TMPDIR:-/tmp}/agent.sock"
tmux -S "$SOCKET" new-session -d -s agent-session
tmux -S "$SOCKET" send-keys -t agent-session "claude --model opus --agent code-critic" Enter

# Interact
tmux -S "$SOCKET" send-keys -t agent-session "Review the auth module for complexity" Enter

# Check output
tmux -S "$SOCKET" capture-pane -p -t agent-session -S -50
```

## Agent Location

All agent definitions live at:
```
~/code/cj/dotfiles/my-claude/agents/
```

## Model Mapping

- `opus` → Claude Opus (deep thinking, complex tasks)
- `sonnet` → Claude Sonnet (fast, capable)
- `inherit` → Use session default

## Quick Reference

```bash
# Code review
claude --model opus --agent code-critic --print "Review src/auth.ts for complexity"

# Architecture
claude --model opus --agent grug-architect --print "Design a caching layer"

# Business analysis  
claude --model opus --agent jared-biz-strategist --print "Analyze market for X"

# PRD creation
claude --model opus --agent tinyprd --print "Create PRD for notification system"

# Game design
claude --model opus --agent game-designer --print "Design combat mechanics for roguelike"

# Image prompts
claude --model sonnet --agent image-prompter --print "Create prompts for fantasy landscape"
```
