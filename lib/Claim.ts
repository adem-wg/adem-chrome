import { importJWK, JWK, jwtVerify, KeyLike } from 'jose';
import { Constraints, ConstraintSet, IP } from './Constraints.js';
import { checkLogPointer } from './ct/api.js';
import { calculateKid } from './keys/hash.js';
import { KeyStore } from './keys/keys.js';
import { decodeBase64UrlText } from './util/bytes.js';

export interface Headers {
  alg: string
  jwk: JWK
  kid: string
  cty: string
}

interface RawHeaders {
  alg?: string
  jwk?: JWK
  kid?: string
  cty?: string
}

export interface LogPointer {
  ver: string
  id: string
  hash?: string
  index?: number
}

export interface Payload {
  iss?: string
  assets?: string[]
  sub?: string
  log?: LogPointer[]
  key?: string
  emb?: Constraints
  iat: number
  nbf: number
  exp: number
}

export interface RawPayload {
  iss?: string
  assets?: string[]
  sub?: string
  log?: LogPointer[]
  key?: string
  emb?: Constraints
  iat?: number
  nbf?: number
  exp?: number
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

async function importHeaders(headers: RawHeaders, keys: KeyStore): Promise<Headers> {
  if (headers.alg === undefined) {
    throw new Error('headers miss signing algorithm');
  } else if (headers.cty !== 'adem-end' && headers.cty !== 'adem-emb') {
    throw new Error('headers contain wrong cty');
  } else {
    let jwk: JWK | undefined;
    if (headers.kid !== undefined) {
      jwk = keys.get(headers.kid)
    } else {
      jwk = headers.jwk
    }

    if (jwk === undefined) {
      throw new Error('headers do not identify verification key')
    } else {
      const kid = await calculateKid(jwk);
      return { jwk, kid, cty: headers.cty, alg: headers.alg };
    }
  }
}

async function importPayload(payload: RawPayload): Promise<Payload> {
  if (payload.iat === undefined || payload.nbf === undefined || payload.exp === undefined) {
    throw new Error('iat/nbf/exp undefined');
  } else {
    const { iss, assets, emb, exp, iat, key, log, nbf, sub } = payload;
    return { iss, assets, emb, exp, iat, key, log, nbf, sub };
  }
}

export async function NewClaim(token: string, keys: KeyStore = new KeyStore()): Promise<Claim> {
  const [headersRaw, payloadRaw] = token.split('.');
  const rawHeaders = JSON.parse(decodeBase64UrlText(headersRaw)) as Headers;
  const rawPayload = JSON.parse(decodeBase64UrlText(payloadRaw)) as Payload;
  return new Claim(token, await importHeaders(rawHeaders, keys), await importPayload(rawPayload));
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
  /** Endorsement/emblem constraints.
   * When emblem, contains assets marked as protected. */
  constraints?: ConstraintSet;

  constructor(token: string, headers: Headers, payload: Payload) {
    this.token = token;
    this.headers = headers;
    this.payload = payload;

    if (this.headers.cty === 'adem-emb') {
      this.constraints = new ConstraintSet({ ...this.payload.emb, assets: this.payload.assets });
    } else {
      this.constraints = new ConstraintSet(this.payload.emb || {});
    }
  }

  async verify(keys: KeyStore, options: VerifyOptions = {}): Promise<void> {
    const key = await this.getVerificationKey(keys, options);
    await jwtVerify(this.token, key as KeyLike);
    if (this.payload.key !== undefined) {
      keys.setAuthenticated(this.payload.key);
    }
  }

  async getVerificationKey(keys: KeyStore, options: VerifyOptions): Promise<KeyLike | Uint8Array> {
    const commitments = this.commitments();
    const iss = this.payload.iss;
    if (commitments !== undefined && commitments.length > 0) {
      if (iss === undefined) {
        throw new Error('root endorsement requires issuer');
      } else {
        if (options.ctVerifier !== undefined) {
          await options.ctVerifier(commitments, iss, this.headers.jwk);
        } else {
          await Promise.all(commitments.map((log) => checkLogPointer(log, new URL(iss), this.headers.kid)));
        }
      }
    } else {
      if (!keys.isAuthenticated(this.headers.kid)) {
        throw new Error(`could not authenticate key ${this.headers.kid}`);
      }
    }

    return importKey(this.headers.jwk);
  }

  commitments(): (LogPointer[] | undefined) {
    return this.payload.log;
  }

  endorsesKey(): (string | undefined) {
    return this.payload.key;
  }

  async marks(ip: IP): Promise<boolean> {
    if (this.payload.key !== undefined) {
      // Endorsements don't mark anything as protected
      return false;
    } else if (this.constraints?.assets === undefined) {
      return false;
    }

    for (const ai of this.constraints.assets) {
      if (ai.moreGeneralThan(ip)) {
        return true;
      }
    }
    return false;
  }
}
export default Claim;
