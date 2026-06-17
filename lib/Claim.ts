import { importJWK, JWK, jwtVerify, KeyLike } from 'jose';
import { Constraints, ConstraintSet, IP } from './Constraints.js';
import { checkInclusion } from './ct/api.js';
import { calculateKid } from './keys/hash.js';
import { KeyStore } from './keys/keys.js';

export interface Headers {
  alg: string
  jwk: JWK
  cty: string
}

interface RawHeaders {
  alg: string
  jwk?: JWK
  kid?: string
  cty: string
}

export interface LogPointer {
  ver: string
  id: string
  hash?: string
  index?: number
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

export interface VerifyOptions {
  ctVerifier?: (logs: LogPointer[], issuer: string, key: JWK) => Promise<void>
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

export async function NewClaim(token: string, keys: KeyStore = new KeyStore()): Promise<Claim> {
  const [headersRaw, payloadRaw] = token.split('.');
  const rawHeaders = JSON.parse(Buffer.from(headersRaw, 'base64url').toString()) as RawHeaders;
  const payload = JSON.parse(Buffer.from(payloadRaw, 'base64url').toString()) as Payload;

  let jwk = rawHeaders.jwk;
  if (jwk !== undefined) {
    jwk = Object.assign({}, jwk, { alg: rawHeaders.alg, kid: await calculateKid(jwk) });
  } else if (rawHeaders.kid !== undefined) {
    jwk = keys.get(rawHeaders.kid);
  }
  if (jwk === undefined) {
    throw new Error('no verification key');
  }

  const headers: Headers = { alg: rawHeaders.alg, cty: rawHeaders.cty, jwk };
  const isRoot = payload.log !== undefined;
  const endorses = headers.cty === 'adem-end' ? payload.key : undefined;
  return new Claim(token, headers, payload, isRoot, endorses);
}

export const parseToken = NewClaim;

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
    if (headers.jwk.kid === undefined) {
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

  async verify(keys: KeyStore, options: VerifyOptions = {}): Promise<void> {
    const key = await this.getVerificationKey(keys, options);
    await jwtVerify(this.token, key as KeyLike);
    if (this.endorses !== undefined) {
      keys.put(this.endorses);
    }
  }

  async getVerificationKey(keys: KeyStore, options: VerifyOptions): Promise<KeyLike | Uint8Array> {
    if (this.isRoot) {
      if (!this.payload.log?.length) {
        throw new Error('root endorsement verification requires log pointers');
      }

      if (options.ctVerifier !== undefined) {
        await options.ctVerifier(this.payload.log, this.payload.iss, this.headers.jwk);
      } else {
        await Promise.all(this.payload.log.map(({ ver, id, hash }) => {
          if (ver !== 'v1' || hash === undefined) {
            return Promise.reject(new Error(`unsupported CT log version ${ver}`));
          }
          return checkInclusion(id, hash, new URL(this.payload.iss), this.headers.jwk.kid as string);
        }));
      }
    } else {
      await keys.isAuthenticated(this.headers.jwk.kid as string);
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
