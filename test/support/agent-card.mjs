// Signs an A2A Agent Card as the A2A specification (8.4) describes: a JWS over the RFC 8785 form of the card without
// `signatures`, appended to the card's `signatures`. Test helper for the catalog importer.
import {sign} from 'node:crypto';
import {canonical} from '../../src/crypto.mjs';

export function signCard(card, privateKey, header) {
  const {signatures, ...unsigned} = card, protectedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const input = `${protectedHeader}.${Buffer.from(canonical(unsigned)).toString('base64url')}`;
  const ec = header.alg.startsWith('ES');
  const signature = sign(header.alg === 'EdDSA' ? null : 'sha256', Buffer.from(input), ec ? {key: privateKey, dsaEncoding: 'ieee-p1363'} : privateKey);
  return {...card, signatures: [...(signatures || []), {protected: protectedHeader, signature: signature.toString('base64url')}]};
}
