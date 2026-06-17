import Claim, { VerifyOptions } from './Claim.js';
import { ConstraintSet } from './Constraints.js';
import { KeyStore } from './keys/keys.js';

/**
 * A set of ADEM claims. Both emblems and endorsement.
 */
class ClaimSet {
  /** Leaf claim */
  emblem: Claim;
  /** Endorsements with the same iss claim as the emblem */
  internals: Claim[] = [];
  /** Endorsements with a different iss claim as the emblem */
  externals: Claim[] = [];
  /** Identity of the emblem issuer. */
  emblemIssuer: string;

  constructor(emblem: Claim, endorsements: Claim[]) {
    this.emblem = emblem;
    this.emblemIssuer = this.emblem.payload.iss;

    const endorsedBy: { [kid: string]: Claim } = {};
    let root: Claim | undefined;
    for (const token of endorsements) {
      if (token.payload.iss !== this.emblem.payload.iss) {
        if (!token.isRoot) {
          throw new Error('every external endorsement must be signed by a root key');
        }
        this.externals.push(token);
      } else if (token.isRoot) {
        root = token;
      } else {
        endorsedBy[token.endorses as string] = token;
      }
    }

    let endorsed = this.emblem.headers.jwk.kid;
    while (endorsed !== root?.headers.jwk.kid) {
      const by = endorsedBy[endorsed as string] as Claim | undefined;
      delete endorsedBy[endorsed as string]; // prevent cycles
      if (by === undefined) {
        break;
      } else {
        this.internals.unshift(by);
        endorsed = by.headers.jwk.kid;
      }
    }

    if (root !== undefined) {
      this.internals.unshift(root);
    }
  }

  async verify(keys: KeyStore, options: VerifyOptions = {}): Promise<ClaimSet> {
    // Verify external endorsements
    let endorsedIssuerRootKid: string | undefined;
    for (const token of this.externals) {
      await token.verify(keys, options);
      if (!endorsedIssuerRootKid) {
        endorsedIssuerRootKid = token.endorses;
      } else if (endorsedIssuerRootKid !== token.endorses) {
        throw new Error('inconsistent external endorsements');
      }
    }

    if (endorsedIssuerRootKid !== undefined && this.internals[0]?.headers.jwk.kid !== endorsedIssuerRootKid) {
      throw new Error('emblem issuer root is not signed by endorsed key');
    }

    for (let token of this.internals) {
      await token.verify(keys, options);
    }
    await this.emblem.verify(keys, options);

    // Check that it matches all constraints
    for (let endorsement of this.externals.concat(this.internals)) {
      if (!(endorsement.constraints as ConstraintSet).permits(this.emblem)) {
        throw new Error('Emblem does not match constraints');
      }
    }

    return this;
  }
}
export default ClaimSet;
