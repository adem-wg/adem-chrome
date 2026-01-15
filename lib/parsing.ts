import Claim, { NewClaim } from './Claim';
import ClaimSet from './ClaimSet';
import { DNSResponse } from './util/dns';
import { allFulfilled, logAndReject } from './util/promise';

const ADEM_R = /adem(-.+)?=(.+)/;

function get<T>(map: any, def: T, ...path: string[]): T | undefined {
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

type IdentMap = { [identifier: string]:string[] };

export function parseTXTs(responses: DNSResponse[]): Promise<ClaimSet[]> {
  const claims = responses.map((rec) => ADEM_R.exec(rec.data))
    .filter((match): match is RegExpExecArray => Boolean(match));

  const tokens: IdentMap = {};
  claims.forEach((claimMatch) => {
    const [ _, identifier, b64 ] = claimMatch;
    get(tokens, [] as string[], identifier || '')?.push(b64);
  });

  const sets: Promise<ClaimSet>[] = [];
  for (const [_, seqs] of Object.entries(tokens)) {
    const claimsP = seqs.map((rawToken) => NewClaim(rawToken));
    const setP = Promise.all(claimsP).then((claims) => {
      const emblems = claims.filter((t) => t.headers.cty === 'adem-emb');
      if (emblems.length !== 1) {
        throw new Error('multiple emblems found')
      }
      const endorsements = claims.filter((t) => t.headers.cty === 'adem-end');
      console.log(`found ${seqs.length} tokens`)

      return new ClaimSet(emblems[0], endorsements);
    });
    sets.push(setP);
  }

  return allFulfilled(sets, console.log);
}
