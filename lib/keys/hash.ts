import { calculateJwkThumbprint, JWK } from 'jose';

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32(input: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of input) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32[(value << (5 - bits)) & 31];
  }
  return output.toLowerCase();
}

export async function calculateKid(jwk: JWK): Promise<string> {
  const digest = await calculateJwkThumbprint(jwk, 'sha256');
  return base32(Buffer.from(digest, 'base64url'));
}

export function readKID(jwk?: JWK): string {
  if (jwk?.kid === undefined) {
    throw new Error('no kid present');
  }
  return jwk.kid;
}
