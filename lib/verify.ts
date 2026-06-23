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
  errors: Error[]
}

function parseKey(raw: string): JWK | undefined {
  try {
    const key = JSON.parse(raw) as JWK;
    return typeof key.kty === 'string' ? key : undefined;
  } catch {
    return undefined;
  }
}

export async function verifyTokens(
  rawTokens: string[],
  trustedKeys: JWK[] = [],
  options: VerifyOptions = {},
): Promise<VerificationResults> {
  const keys = new KeyStore();
  for (const key of trustedKeys) {
    const kid = await keys.add(key);
    keys.setAuthenticated(kid);
  }

  const tokens: string[] = [];
  for (const raw of rawTokens) {
    const key = parseKey(raw);
    if (key === undefined) {
      tokens.push(raw);
    } else {
      await keys.add(key);
    }
  }

  const claims = await Promise.all(tokens.map((token) => NewClaim(token)));
  const set = new ClaimSet();
  await set.verify(claims, keys, options);

  let results: VerificationResult[] = [];
  if (set.emblem === undefined) {
    results = [VerificationResult.INVALID];
  } else {
    results.push(VerificationResult.SIGNED);
    if (set.internals[0]?.payload.iss !== undefined) {
      results.push(VerificationResult.ORGANIZATIONAL);
      if (set.externals.length > 0) {
        results.push(VerificationResult.ENDORSED);
      }
    }
  }
  return {
    results,
    protected: set.emblem?.payload.assets || [],
    issuer: set.emblem?.payload.iss,
    endorsedBy: set.externals.map((claim) => claim.payload.iss).filter((iss) => iss !== undefined),
    errors: set.errors,
  };
}
