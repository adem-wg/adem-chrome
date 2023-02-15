import Claim from './Claim';
import { ConstraintSet } from './Constraints';

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
  /** Identity of the claiming protected party. */
  pp: string;

  constructor(emblem: Claim, endorsements: Claim[]) {
    this.emblem = emblem;
    this.pp = this.emblem.payload.iss;

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

    let endorsed = this.emblem.verificationKID;
    while (endorsed !== root?.verificationKID) {
      const by = endorsedBy[endorsed as string] as Claim | undefined;
      delete endorsedBy[endorsed as string]; // prevent cycles
      if (by === undefined) {
        break;
      } else {
        this.internals.unshift(by);
        endorsed = by.verificationKID;
      }
    }

    if (root !== undefined) {
      this.internals.unshift(root);
    }
  }

  async verify(): Promise<ClaimSet> {
    // Verify external endorsements
    let endorsedPPRootKID: string | undefined;
    for (const token of this.externals) {
      await token.verify();
      if (!endorsedPPRootKID) {
        endorsedPPRootKID = token.endorses;
      } else if (endorsedPPRootKID !== token.endorses) {
        throw new Error('inconsistent external endorsements');
      }
    }

    if (this.internals[0].verificationKID !== endorsedPPRootKID) {
      throw new Error('PP root is not signed by endorsed key');
    }

    for (let token of this.internals) {
      await token.verify();
    }
    await this.emblem.verify();

    // Check that it matches all constraints
    for (let endorsement of this.externals.concat(this.internals)) {
      if ((endorsement.constraints as ConstraintSet).permits(this.emblem)) {
        throw new Error('Emblem does not match constraints');
      }
    }

    return this;
  }
}
export default ClaimSet;
