import { importJWK, JWK, jwtVerify, KeyLike } from 'jose';
import { Constraints, ConstraintSet, IP } from './Constraints';
import { checkInclusion } from './ct/api';
import { readKID } from './keys/hash';
import { isAuthenticated, put } from './keys/keys';

export interface Headers {
  alg: string
  jwk: JWK
  cty: string
}

export interface LogPointer {
  ver: string
  id: string
  hash: string
}

export interface Payload {
  ver: string
  iss: string
  assets?: string[]
  sub?: string
  log?: LogPointer[]
  key?: string
  emb?: Constraints
  iat: number
  nbf: number
  exp: number
}

function importKey(key: JWK | undefined): Promise<KeyLike | Uint8Array> {
  if (key === undefined) {
    return Promise.reject(new Error('key undefined'));
  } else if (key.alg === undefined) {
    return Promise.reject(new Error('keys require alg parameter'));
  } else {
    return importJWK(key, key.alg as string);
  }
}

export async function NewClaim(token: string): Promise<Claim> {
  const [headersRaw, payloadRaw] = token.split('.');
  const headers = JSON.parse(window.atob(headersRaw)) as Headers;
  const payload = JSON.parse(window.atob(payloadRaw)) as Payload;
  // What key should be used for verification?
  const isRoot = payload.log !== undefined;
  const verificationKID = readKID(headers.jwk);
  const endorses = payload.sub !== undefined ? payload.key : undefined;
  return new Claim(token, headers, payload, isRoot, endorses);
}

/**
 * Parses an ADEM claim which can be both an emblem or an endorsement.
 */
class Claim {
  /** Compat JWS representation of the claim */
  token: string;
  /** Decoded headers of the JWS */
  headers: Headers;
  /** Decoded payload */
  payload: Payload;
  /** True if this claim is an endorsement signed by a root key. */
  isRoot: boolean;
  /** Which key is endorsed by this claim? If null, this claim is an emblem. */
  endorses?: string;
  /** Endorsement/emblem constraints.
   * When emblem, contains assets marked as protected. */
  constraints?: ConstraintSet;

  constructor(token: string, headers: Headers, payload: Payload, isRoot?: boolean, endorses?: string) {
    if (headers.jwk === undefined) {
      throw new Error('no verification key');
    } else if (headers.jwk.kid === undefined) {
      throw new Error('header key misses kid');
    }

    this.token = token;
    this.headers = headers;
    this.payload = payload;
    this.isRoot = isRoot !== undefined && isRoot;
    if (endorses === undefined) {
      if (this.payload.assets === undefined) {
        throw new Error('emblem must mark assets');
      }
      this.constraints = new ConstraintSet(
        Object.assign(this.payload.emb || {}, { ass: this.payload.assets })
      );
    } else {
      this.endorses = endorses;
      this.constraints = new ConstraintSet(this.payload.emb || {});
    }
  }

  async verify(): Promise<void> {
    const key = await this.getVerificationKey();
    // On reject, await jwtVerify will throw
    await jwtVerify(this.token, key as KeyLike);
    if (this.endorses !== undefined) {
      await put(this.endorses);
    }
  }

  async getVerificationKey(): Promise<KeyLike | Uint8Array> {
    if (this.isRoot) {
      if (!this.payload.log?.length) {
        throw new Error('root endorsement verification requires log pointers');
      }

      // await will throw when *any* promise is rejected
      await Promise.all(
        this.payload.log.map(({ id, hash }) => checkInclusion(
          id,
          hash,
          new URL(this.payload.iss),
          // This assumes that KID was calculated. This invariant is established
          // in verify(...).
          this.headers.jwk.kid as string,
        )),
      );
    } else {
      await isAuthenticated(this.headers.jwk.kid as string);
    }

    return importKey(this.headers.jwk);
  }

  async marks(ip: IP): Promise<boolean> {
    if (this.endorses !== undefined) {
      // Endorsements don't mark anything as protected
      return false;
    } else if (this.constraints?.ass === undefined) {
      return false;
    }

    for (const ai of this.constraints.ass) {
      if (ai.moreGeneralThan(ip)) {
        return true;
      }
    }
    return false;
  }
}
export default Claim;
