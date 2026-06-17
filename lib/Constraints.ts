import Claim from './Claim.js';
import ipaddr from 'ipaddr.js';

export interface Constraints {
  assets?: string[]
  prp?: string[]
  dst?: string[]
  wnd?: number
}

export type IP = ipaddr.IPv4 | ipaddr.IPv6;

const IPv6_R = /\[([/a-f\d:]+)\]:?(\d+)?/;

export class AI {
  constraint: string | IP | [IP, number];
  port?: number = undefined;

  constructor(from: string) {
    const ipMatch = IPv6_R.exec(from);
    if (ipMatch !== null) {
      try {
        this.constraint = ipaddr.parseCIDR(ipMatch[1]);
      } catch {
        this.constraint = ipaddr.parse(ipMatch[1]);
      }
      if (ipMatch[2] !== undefined) {
        this.port = parseInt(ipMatch[2]);
      }
    } else {
      this.constraint = from.toLowerCase();
    }
  }

  moreGeneralThan(ai: AI | IP): boolean {
    const constraint = ai instanceof AI ? ai.constraint : ai;
    if (typeof this.constraint === 'string') {
      if (typeof constraint !== 'string') {
        return false;
      } else if (this.constraint.startsWith('*.')) {
        const suffix = this.constraint.slice(1);
        return constraint === this.constraint.slice(2) || constraint.endsWith(suffix);
      } else {
        return constraint === this.constraint;
      }
    } else if (typeof constraint === 'string') {
      return false;
    } else if (this.constraint instanceof Array) {
      if (constraint instanceof Array) {
        if (this.constraint[1] > constraint[1]) {
          // If this prefix is longer than the given, it cannot be more general
          // than the given.
          return false;
        } else {
          return constraint[0].match(this.constraint);
        }
      } else {
        return constraint.match(this.constraint);
      }
    } else {
      if (constraint instanceof Array) {
        // An address cannot be more general than a prefix
        return false;
      } else {
        return constraint.match(this.constraint, 64);
      }
    }
  }

  anyMoreGeneral(ais: AI[]): boolean {
    for (const ai of ais) {
      if (ai.moreGeneralThan(this)) {
        return true;
      }
    }
    return false;
  }
}

export class ConstraintSet {
  assets?: AI[];
  prp?: number;
  dst?: number;
  wnd?: number;

  constructor(constraints: Constraints) {
    if (constraints.assets) {
      this.assets = constraints.assets.map((v) => new AI(v));
    }

    if (constraints.prp !== undefined) {
      this.prp = 0;
      for (const constraint of constraints.prp) {
        switch (constraint) {
          case "protective": this.prp |= 0b01; break;
          case "indicative": this.prp |= 0b10; break;
        }
      }
    }

    if (constraints.dst !== undefined) {
      this.dst = 0;
      for (const constraint of constraints.dst) {
        switch (constraint) {
          case "protective": this.dst |= 0b01; break;
          case "indicative": this.dst |= 0b10; break;
        }
      }
    }
  }

  permits(emblem: Claim): boolean {
    const { assets, nbf, exp } = emblem.payload;
    if (assets === undefined) {
      throw new Error('Can only check emblems');
    }

    // emb will be defined on emblems
    const { constraints } = emblem;
    if (this.assets !== undefined && !constraints?.assets?.reduce((aggr, v) => aggr && v.anyMoreGeneral(this.assets as AI []), true)) {
      return false;
    }

    if (this.prp !== undefined && !Boolean(this.prp & (constraints?.prp || 0))) {
      return false;
    } else if (this.dst !== undefined && !Boolean(this.dst & (constraints?.dst || 0))) {
      return false;
    } else if (this.wnd !== undefined && this.wnd < exp - nbf) {
      return false;
    } else {
      return true;
    }
  }
}

export function parseAssetIdentifier(raw: string): AI {
  return new AI(raw);
}
