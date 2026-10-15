#!/usr/bin/env node
// Claude Code PreToolUse/PostToolUse hook -> EvidScope ingest (docs/agent-monitoring.md). Installed by
// scripts/install-agent-monitoring.mjs as `node <dir>/scripts/claude-code-hook.mjs` in ~/.claude/settings.json; the work, and the
// guarantee that it never blocks or changes the tool call, is src/agent-hook-runner.mjs.
import {runHook} from '../src/agent-hook-runner.mjs';

await runHook('claude-code');
