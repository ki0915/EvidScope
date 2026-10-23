// The one function through which the vault signs DSSE attestations (docs/receipts.md). A separate signer process can take
// its place: any {keyid, publicKey, sign(message) -> signature or promise} for the vault key works unchanged, and the vault
// checks every returned signature against publicKey before an envelope leaves it.
import {createPublicKey, sign} from 'node:crypto';
import {keyFingerprint} from './dsse.mjs';

export function attestationSigner(privateKey) {
  const publicKey = createPublicKey(privateKey);
  return {keyid: keyFingerprint(publicKey), publicKey, sign: async message => sign(null, message, privateKey)};
}
