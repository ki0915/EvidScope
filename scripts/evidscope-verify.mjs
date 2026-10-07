// Offline verifier for EvidScope evidence; see src/verify-cli.mjs and docs/receipts.md. Published separately by
// scripts/package-verifier.mjs with the same entry name.
import {main} from '../src/verify-cli.mjs';

process.exitCode = main(process.argv.slice(2));
