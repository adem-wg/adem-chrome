import Claim, { NewClaim } from './Claim';
import ClaimSet from './ClaimSet';
import { DNSResponse } from './util/dns';
import { allFulfilled, logAndReject } from './util/promise';

const ADEM_R = /adem-(emb|end)(-\w+[\w\d]*)?-(\d+)(-p(\d+))?=(.+)/;

function get(map: any, def: any, ...path: string[]): any {
  if (path.length === 0) {
    return undefined;
  }

  let iter = map;
  const lastI = path.pop() as string;
  for (const component of path) {
    if (iter[component] === undefined) {
      iter[component] = {};
    }
    iter = iter[component];
  }

  if (iter[lastI] === undefined) {
    iter[lastI] = def;
  }
  return iter[lastI];
}

type SeqMap = { [seq: string]: string[] };
type IdentSeqMap = { [identifier: string]:SeqMap };

export function parseTXTs(responses: DNSResponse[]): Promise<ClaimSet[]> {
  const claims = responses.map((rec) => ADEM_R.exec(rec.data))
    .filter((match): match is RegExpExecArray => Boolean(match));

  const partialEmblems: IdentSeqMap = {};
  const partialEndorsements: IdentSeqMap = {};
  claims.forEach((claimMatch) => {
    const [ m, type, identifier, seq, partStr, part, b64 ] = claimMatch;
    let partial;
    switch (type) {
      case 'emb': partial = partialEmblems; break;
      case 'end': partial = partialEndorsements; break;
      default: return;
    }
    get(partial, [], identifier || '', seq)[parseInt(part || '0')] = b64;
  });

  const sets: Promise<ClaimSet>[] = [];
  for (const [ident, seqs] of Object.entries(partialEmblems)) {
    const emblems = Object.values(seqs).map((parts) => NewClaim(parts.join('')));
    if (emblems.length < 1) {
      continue;
    }
    if (emblems.length > 1) {
      throw new Error('Can only have one emblem per identifier');
    }
    const emblem = logAndReject(emblems[0], (r) => {
      console.error('could not create emblem');
      if (r instanceof Error) {
        console.error(r);
      }
    });

    const endorsements = Object.values(get(partialEndorsements, {}, ident) as SeqMap)
      .map((parts) => NewClaim(parts.join('')));

    const endPs = allFulfilled(endorsements, (r) => {
      console.error('could not create endorsement');
      if (r instanceof Error) {
        console.error(r);
      }
    });
    const setP = Promise.all([emblem, endPs]).then(([emb, endPs]) => new ClaimSet(emb, endPs));
    sets.push(setP);
  }

  return allFulfilled(sets);
}
