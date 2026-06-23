import Claim, { VerifyOptions } from './Claim.js';
import { ConstraintSet } from './Constraints.js';
import { KeyStore } from './keys/keys.js';

/**
 * A set of ADEM claims. Both emblems and endorsement.
 */
class ClaimSet {
  /** Leaf claim */
  emblem?: Claim;
  /** Endorsements with the same iss claim as the emblem */
  internals: Claim[] = [];
  /** Endorsements with a different iss claim as the emblem */
  externals: Claim[] = [];
  /** Errors that occurred during set verification. */
  errors: Error[] = [];

  async verify(tokens: Claim[], keys: KeyStore, options: VerifyOptions = {}): Promise<ClaimSet> {
    const emblems = tokens.filter((token) => token.headers.cty === 'adem-emb');
    if (emblems.length !== 1) {
      this.errors.push(new Error('token set must contain exactly one emblem'));
      return this;
    }

    const emblem = emblems[0];
    const endorsements = tokens.filter((token) => token.headers.cty === 'adem-end');
    const externals: Claim[] = [];
    const internals: Claim[] = [];
    const endorsedBy: { [kid: string]: Claim } = {};
    let root: Claim | undefined;

    // Construct verification dependencies
    for (const token of endorsements) {
      const endorses = token.endorsesKey();
      if (endorses === undefined) {
        this.errors.push(new Error('endorsement endorses no key'));
      } else if (token.payload.iss !== emblem.payload.iss) {
        externals.push(token);
      } else if (token.commitments() !== undefined) {
        root = token;
      } else {
        // TODO: This might allow an adversary to prevent verification by adding
        // tokens that overwrite intermediate endorsements.
        endorsedBy[endorses as string] = token;
      }
    }

    // Build array of internal endorsements in correct order
    let endorsed = emblem.headers.kid;
    while (endorsed !== root?.headers.jwk.kid) {
      if (endorsed in endorsedBy) {
        const by = endorsedBy[endorsed as string];
        internals.unshift(by);
        endorsed = by.headers.kid;
      } else {
        break;
      }
      delete endorsedBy[endorsed as string]; // prevent cycles
    }

    if (root !== undefined) {
      internals.unshift(root);
    }

    if (internals.length > 0) {
      // Verify external endorsements
      for (const token of externals) {
        if (token.commitments() === undefined) {
          this.errors.push(new Error('external endorsements lack root key commitment'));
        } else if (token.payload.sub !== internals[0].payload.iss) {
          this.errors.push(new Error('external endorsement sub does not match root iss'));
        } else if (token.endorsesKey() !== internals[0].headers.kid) {
          this.errors.push(new Error('external keys does not match root key id'));
        } else {
          try {
            await token.verify(keys, options);
            this.externals.push(token);
          } catch (err) {
            this.errors.push(error(err));
            continue;
          }
        }
      }
    }

    for (const token of internals) {
      if (token.payload.sub !== emblem.payload.iss) {
        this.errors.push(new Error('internal endorsement with wrong sub'));
      } else {
        try {
          await token.verify(keys, options);
          this.internals.push(token);
        } catch (err) {
          this.errors.push(error(err));
        }
      }
    }

    try {
      await emblem.verify(keys, options);
      this.emblem = emblem;
      this.filterPermitted();
    } catch (err) {
      this.errors.push(error(err));
    }

    return this;
  }

  filterPermitted() {
    const emblem = this.emblem;
    if (emblem === undefined) {
      return;
    }

    const aux = (endorsement: Claim) => {
      try {
        if (!(endorsement.constraints as ConstraintSet).permits(emblem)) {
          this.errors.push(new Error('Emblem does not match constraints'));
          return false;
        }
      return true;
      } catch (err) {
        this.errors.push(error(err));
        return false;
      }
    }

    this.externals = this.externals.filter(aux);
    this.internals = this.internals.filter(aux);
  }
}

function error(err: unknown): Error {
  return err instanceof Error ? err : new Error(`unknown error: ${String(err)}`);
}

export default ClaimSet;
