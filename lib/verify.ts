import { JWK } from 'jose';
import { NewClaim, VerifyOptions } from './Claim.js';
import ClaimSet from './ClaimSet.js';
import { KeyStore } from './keys/keys.js';

export enum VerificationResult {
  INVALID = 'INVALID',
  SIGNED = 'SIGNED',
  ORGANIZATIONAL = 'ORGANIZATIONAL',
  ENDORSED = 'ENDORSED',
}

export interface VerificationResults {
  results: VerificationResult[]
  protected: string[]
  issuer?: string
  endorsedBy: string[]
}

function parseKey(raw: string): JWK | undefined {
  try {
    const key = JSON.parse(raw) as JWK;
    return typeof key.kty === 'string' ? key : undefined;
  } catch {
    return undefined;
  }
}

function invalid(): VerificationResults {
  return {
    results: [VerificationResult.INVALID],
    protected: [],
    endorsedBy: [],
  };
}

export async function verifyTokens(
  rawTokens: string[],
  trustedKeys: JWK[] = [],
  options: VerifyOptions = {},
): Promise<VerificationResults> {
  const keys = new KeyStore();
  for (const key of trustedKeys) {
    keys.put(await keys.add(key));
  }

  const tokens: string[] = [];
  for (const raw of rawTokens) {
    const key = parseKey(raw);
    if (key === undefined) {
      tokens.push(raw);
    } else {
      keys.put(await keys.add(key));
    }
  }

  try {
    const claims = await Promise.all(tokens.map((token) => NewClaim(token, keys)));
    const emblems = claims.filter((claim) => claim.headers.cty === 'adem-emb');
    if (emblems.length !== 1) {
      throw new Error('token set must contain exactly one emblem');
    }
    const set = new ClaimSet(emblems[0], claims.filter((claim) => claim.headers.cty === 'adem-end'));
    await set.verify(keys, options);

    const results = [VerificationResult.SIGNED];
    if (set.internals[0]?.isRoot) {
      results.push(VerificationResult.ORGANIZATIONAL);
    }
    if (set.externals.length > 0) {
      results.push(VerificationResult.ENDORSED);
    }
    return {
      results,
      protected: set.emblem.payload.assets || [],
      issuer: set.pp,
      endorsedBy: set.externals.map((claim) => claim.payload.iss),
    };
  } catch {
    return invalid();
  }
}
