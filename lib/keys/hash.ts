import { calculateJwkThumbprint, JWK } from 'jose';
import { base32 } from 'rfc4648';

export async function calculateKid(jwk: JWK): Promise<string> {
  const digest = await calculateJwkThumbprint(jwk, 'sha256');
  return base32.stringify(Buffer.from(digest, 'base64url'), { pad: false }).toLowerCase();
}
