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

export async function verifyTokens(
  tokens: string[],
  untrustedKeys: JWK[] = [],
  trustedKeys: JWK[] = [],
  options: VerifyOptions = {},
): Promise<VerificationResults> {
  const keys = new KeyStore();
  for (const key of untrustedKeys) {
    await keys.add(key);
  }
  for (const key of trustedKeys) {
    const kid = await keys.add(key);
    keys.setAuthenticated(kid);
  }

  const claimPs = await Promise.allSettled(tokens.map((token) => NewClaim(token, keys)));
  const claims = claimPs.filter((res) => res.status === 'fulfilled').map((res) => res.value);
  const parserErrs = claimPs.filter((res) => res.status === 'rejected').map((res) => new Error(`could not parse token: ${res.reason}`));
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
    errors: set.errors.concat(parserErrs),
  };
}
