// Stand-in for a cloud KMS CLI behind the signer's command backend: reads the message on stdin and prints a signature.
//   node test/support/fake-signer-command.mjs MODE KEY.pem
// MODE: base64 | raw (pure Ed25519), prehash (Ed25519 over SHA-512(message), standing in for a prehash variant such as AWS
// ED25519_PH_SHA_512), canned (always the signature of the self-test vector), fail (exit 3), slow (never answers).
import {createHash, createPrivateKey, sign} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {SELF_TEST_VECTOR} from '../../src/signer-backends.mjs';

const [mode, keyFile] = process.argv.slice(2), key = createPrivateKey(readFileSync(keyFile));
const parts = [];
for await (const chunk of process.stdin) parts.push(chunk);
const message = Buffer.concat(parts);
if (mode === 'fail') { process.stderr.write('AccessDeniedException: not authorized to use this key\n'); process.exit(3); }
if (mode === 'slow') await new Promise(() => setInterval(() => {}, 1000));
const data = mode === 'prehash' ? createHash('sha512').update(message).digest() : mode === 'canned' ? SELF_TEST_VECTOR : message;
const signature = sign(null, data, key);
process.stdout.write(mode === 'raw' ? signature : signature.toString('base64') + '\n');
