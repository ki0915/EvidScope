#!/usr/bin/env node
// Claude Code PreToolUse/PostToolUse hook -> EvidScope ingest (docs/agent-monitoring.md). Installed by
// scripts/install-agent-monitoring.mjs as `node <dir>/scripts/claude-code-hook.mjs` in ~/.claude/settings.json; the work, and the
// guarantee that it changes no tool call unless the guard is on (then it denies only the calls src/agent-hook-guard.mjs names), is
// src/agent-hook-runner.mjs.
import {runHook} from '../src/agent-hook-runner.mjs';

await runHook('claude-code');
