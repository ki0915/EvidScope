#!/usr/bin/env node
// Codex CLI PreToolUse/PostToolUse hook -> EvidScope ingest (docs/agent-monitoring.md). Installed by
// scripts/install-agent-monitoring.mjs --agent codex as `node <dir>/scripts/codex-hook.mjs` in ~/.codex/hooks.json, which Codex runs
// only after the user trusts it (/hooks in the Codex CLI); the work is src/agent-hook-runner.mjs.
import {runHook} from '../src/agent-hook-runner.mjs';

await runHook('codex');
