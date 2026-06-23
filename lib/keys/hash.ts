import { calculateJwkThumbprint, JWK } from 'jose';
import { base32, base64url } from 'rfc4648';

export async function calculateKid(jwk: JWK): Promise<string> {
  delete jwk.kid;
  const digest = await calculateJwkThumbprint(jwk, 'sha256');
  return base32.stringify(base64url.parse(digest, { loose: true }), { pad: false }).toLowerCase();
}
