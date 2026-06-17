import { JWK } from 'jose';
import { DNSResponse, queryTXT } from './util/dns.js';

const ADEM_R = /^adem-(token|key)(?:-.+)?=(.+)$/;

export type TXTRecord = string | string[] | DNSResponse;

export interface DNSMaterial {
  tokens: string[]
  keys: JWK[]
}

function recordText(record: TXTRecord): string {
  const data = typeof record === 'string' || Array.isArray(record) ? record : record.data;
  if (Array.isArray(data)) {
    return data.join('');
  }
  if (data.startsWith('"')) {
    return (JSON.parse(`[${data.replace(/"\s+"/g, '","')}]`) as string[]).join('');
  }
  return data;
}

export function parseTXTRecords(records: TXTRecord[]): DNSMaterial {
  const result: DNSMaterial = { tokens: [], keys: [] };
  for (const record of records) {
    const data = recordText(record);
    const match = ADEM_R.exec(data);
    if (match === null) {
      continue;
    }
    if (match[1] === 'token') {
      result.tokens.push(match[2]);
    } else {
      result.keys.push(JSON.parse(match[2]) as JWK);
    }
  }
  return result;
}

export const parseTXTs = parseTXTRecords;

export function fetchDnsTokens(host: string): Promise<DNSMaterial> {
  return queryTXT(host).then(parseTXTRecords);
}
