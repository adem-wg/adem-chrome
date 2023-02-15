import canonicalize from 'canonicalize';
import base32Encode from 'base32-encode';

// These are all keys that a JWK JSON can have as by RFC7515 and RFC7518, except
// for "kid", which will be recalculated anyways.
const KEYS = [
  "kty", "use", "key_ops", "alg", "x5u", "x5c", "x5t", "x5t#S256", "crv", "x",
  "y", "d", "e", "p", "q", "dp", "dq", "qi", "oth", "r", "t", "k",
];

function restrict(json: object): object {
  const picked = {};
  for (const k of KEYS) {
    if ((json as any)[k] !== undefined) {
      (picked as any)[k] = (json as any)[k];
    }
  }
  return picked;
}

export function calculateKID(jwk?: object): Promise<string> {
  if (jwk === undefined) {
    return Promise.reject(new Error('cannot calculate kid without key'));
  }

  const encoder = new TextEncoder();
  const data = encoder.encode(canonicalize(restrict(jwk)));
  return window.crypto.subtle.digest('SHA-256', data).then((buf) => {
    return base32Encode(buf, 'RFC4648').toLowerCase().replaceAll('=', '');
  });
}

export function readKID(jwk?: object): Promise<string> {
  if (jwk === undefined) {
    return Promise.reject(new Error('cannot read kid from no key'));
  }

  if ((jwk as any).kid !== undefined) {
    return Promise.resolve((jwk as any).kid);
  } else {
    return calculateKID(jwk);
  }
}
