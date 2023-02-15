import { JWK, KeyLike } from 'jose';
import { calculateKID } from './hash';

const keys: { [kid: string]: KeyLike | Uint8Array } = {};

export function get(kid: string): Promise<KeyLike | Uint8Array> {
  if (kid in keys) {
    return Promise.resolve(keys[kid]);
  } else {
    return Promise.reject(new Error(`no key with kid ${kid}`));
  }
}

export function put(kid: string, key: KeyLike | Uint8Array) {
  keys[kid] = key;
}
