import { decodeLeafInput, getSubjectAltNames, getStaticEntryCertificate } from './bin.js'
import { fetchAllLogs, LogMap } from './logs.js'
import type { LogPointer } from '../Claim.js'

let logs: LogMap;
function fetchLogs(): Promise<LogMap> {
  if (logs === undefined) {
    return fetchAllLogs().then(logMap => {
      logs = logMap;
      return logs;
    })
  } else {
    return Promise.resolve(logs);
  }
}

function joinLogPath(logUrl: string, path: string): string {
  return `${logUrl.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`;
}

function logQuery(logUrl: string, path: string, params?: URLSearchParams): Promise<Response> {
  let q = joinLogPath(logUrl, path);
  if (params !== undefined) {
    q += '?' + params.toString();
  }
  return fetch(q).then((resp) => {
    return resp.ok ? resp : Promise.reject(new Error(`CT query failed with status ${resp.status}`));
  });
}

function logQueryJSON<T>(logUrl: string, path: string, params?: URLSearchParams): Promise<T> {
  return logQuery(logUrl, path, params).then((resp) => resp.json() as Promise<T>);
}

interface STHResponse {
  tree_size: number
  timestamp: number
}

interface ProofByHashResponse {
  leaf_index: number
}

interface EntryResponse {
  leaf_input: string
  extra_data: string
}

interface EntriesResponse {
  entries: EntryResponse[]
}

function checkBinding(names: string[], iss: URL, keyHash: string): void {
  if (!(names.includes(`adem-configuration.${iss.host}`) || names.includes(iss.host))) {
    throw new Error('issuer not in certificate names');
  } else if (!(names.includes(`${keyHash}.adem-configuration.${iss.host}`))) {
    throw new Error('key hash not in certificate names');
  }
}

export async function checkInclusionV1(logId: string, leafHash: string, iss: URL, keyHash: string): Promise<void> {
  let log = (await fetchLogs())[logId];
  if (log === undefined) {
    throw new Error('cannot verify log inclusion without log info');
  } else if (log.url === undefined) {
    throw new Error('cannot verify v1 log inclusion without v1 log URL');
  } else {
    const logUrl = log.url;
    await logQueryJSON<STHResponse>(logUrl, 'ct/v1/get-sth')
      .then((sth) =>
        logQueryJSON<ProofByHashResponse>(
          logUrl,
          'ct/v1/get-proof-by-hash',
          new URLSearchParams({ hash: leafHash, tree_size: sth.tree_size.toString() }),
        ).then((resp) => logQueryJSON<EntriesResponse>(
          logUrl,
          'ct/v1/get-entries',
          new URLSearchParams({
            start: resp.leaf_index.toString(),
            end: resp.leaf_index.toString(),
          }),
        ))
      ).then(async (resp) => {
        if (resp.entries.length != 1) {
          throw new Error('wrong number of certificates returned');
        }

        const cert = decodeLeafInput(resp.entries[0].leaf_input)
        checkBinding(getSubjectAltNames(cert), iss, keyHash);
      });
  }
}

function parseCheckpointTreeSize(checkpoint: string): number {
  const lines = checkpoint.split('\n');
  const treeSize = Number(lines[1]);
  if (!Number.isSafeInteger(treeSize) || treeSize < 0) {
    throw new Error('invalid static CT checkpoint');
  }
  return treeSize;
}

function encodeTileNumber(n: number): string {
  const chunks = [String(n % 1000).padStart(3, '0')];
  while (n >= 1000) {
    n = Math.floor(n / 1000);
    chunks.unshift(`x${String(n % 1000).padStart(3, '0')}`);
  }
  return chunks.join('/');
}

function staticDataTilePath(index: number, treeSize: number): string {
  const tileWidth = 256;
  const tileNumber = Math.floor(index / tileWidth);
  const width = Math.min(tileWidth, treeSize - tileNumber * tileWidth);
  const partial = width < tileWidth ? `.p/${width}` : '';
  return `tile/data/${encodeTileNumber(tileNumber)}${partial}`;
}

export async function checkInclusionStatic(logId: string, index: number, iss: URL, keyHash: string): Promise<void> {
  if (!Number.isSafeInteger(index) || index < 0) {
    throw new Error('invalid static CT leaf index');
  }

  let log = (await fetchLogs())[logId];
  if (log === undefined) {
    throw new Error('cannot verify static log inclusion without log info');
  } else if (log.monitoring_url === undefined) {
    throw new Error('cannot verify static log inclusion without monitoring URL');
  }

  const checkpoint = await logQuery(log.monitoring_url, 'checkpoint').then((resp) => resp.text());
  const treeSize = parseCheckpointTreeSize(checkpoint);
  if (index >= treeSize) {
    throw new Error('static CT leaf index beyond checkpoint tree size');
  }

  const tile = await logQuery(log.monitoring_url, staticDataTilePath(index, treeSize))
    .then((resp) => resp.arrayBuffer());
  const cert = getStaticEntryCertificate(tile, index);
  checkBinding(getSubjectAltNames(cert), iss, keyHash);
}

export async function checkLogPointer(
  log: LogPointer,
  iss: URL,
  keyHash: string,
): Promise<void> {
  switch (log.ver) {
    case 'v1':
      if (log.hash === undefined) {
        throw new Error('missing v1 CT leaf hash');
      }
      return checkInclusionV1(log.id, log.hash, iss, keyHash);
    case 'static':
      if (log.index === undefined) {
        throw new Error('missing static CT leaf index');
      }
      return checkInclusionStatic(log.id, log.index, iss, keyHash);
    default:
      throw new Error(`unsupported CT log version ${log.ver}`);
  }
}
