import ipaddr from 'ipaddr.js';

export interface DNSResponse {
  name: string
  type: number
  TTL: number
  data: string
}

export interface GoogleDNSBody {
  Status: number
  Answer?: DNSResponse[]
}

type GoogleDNSResponse = Omit<DNSResponse, 'data'> & { data: string | string[] };

function dnsQuery(host: string, type: string): Promise<DNSResponse[]> {
  return fetch(`https://dns.google.com/resolve?name=${host}&type=${type}`)
    .then((resp) => {
      if (!resp.ok) {
        return Promise.reject(new Error(`response not okay - status ${resp.status}`));
      } else {
        return resp.json();
      }
    })
    .then((json: GoogleDNSBody) => {
      if (json.Status === 0 && 'Answer' in json) {
        return Promise.resolve(json.Answer as DNSResponse[]);
      } else if (json.Status === 3) { // name does not exit
        return Promise.resolve([]);
      } else {
        return Promise.reject(new Error(`could not resolve ${host}`));
      }
    });
}

function parseALike(resp: DNSResponse[]): (ipaddr.IPv4 | ipaddr.IPv6)[] {
  return resp.map((r) => ipaddr.parse(r.data));
}

function parseTXT(resp: GoogleDNSResponse[]): DNSResponse[] {
  return resp.map((r) => ({
    ...r,
    data: Array.isArray(r.data) ? r.data.join('') : r.data,
  }));
}

export function queryTXT(host: string): Promise<DNSResponse[]> {
  return dnsQuery(host, 'TXT').then(parseTXT);
}

export function queryA(host: string): Promise<(ipaddr.IPv4 | ipaddr.IPv6)[]> {
  return dnsQuery(host, 'A').then(parseALike);
}

export function queryAAAA(host: string): Promise<(ipaddr.IPv4 | ipaddr.IPv6)[]> {
  return dnsQuery(host, 'AAAA').then(parseALike);
}
