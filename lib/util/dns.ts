import ipaddr from 'ipaddr.js';

export interface DNSResponse {
  name: string
  type: number
  TTL: number
  data: string
}

export interface GoogleDNSBody {
  Answer?: DNSResponse[]
}

function dnsQuery(host: string, type: string): Promise<DNSResponse[]> {
  return fetch(`https://dns.google.com/resolve?name=${host}&type=${type}`)
    .then((resp) => {
      if (!resp.ok) {
        return Promise.reject(new Error(`response not okay - status ${resp.status}`));
      } else {
        return resp.json();
      }
    })
    .then((json) => {
      if ('Answer' in json) {
        return Promise.resolve(json.Answer as DNSResponse[]);
      } else {
        return Promise.reject(new Error('response does not contain answer'));
      }
    });
}

function parseALike(resp: DNSResponse[]): (ipaddr.IPv4 | ipaddr.IPv6)[] {
  return resp.map((r) => ipaddr.parse(r.data));
}

export function queryTXT(host: string) {
  return dnsQuery(host, 'TXT');
}

export function queryA(host: string) {
  return dnsQuery(host, 'A').then(parseALike);
}

export function queryAAAA(host: string) {
  return dnsQuery(host, 'AAAA').then(parseALike);
}
