import { getSubjectAltNames } from './bin'
import { fetchAllLogs, LogMap } from './logs'

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

function logQuery<T>(logUrl: string, path: string, params?: URLSearchParams): Promise<T> {
  let q = logUrl + path;
  if (params !== undefined) {
    q += '?' + params.toString();
  }
  return fetch(q).then((resp) => resp.json() as Promise<T>);
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

export async function checkInclusion(logId: string, leafHash: string, iss: URL, keyHash: string): Promise<void> {
  let log = (await fetchLogs())[logId];
  if (log === undefined) {
    throw new Error('cannot verify log inclusion without log info');
  } else {
    await logQuery<STHResponse>(log.url, 'ct/v1/get-sth')
      .then((sth) =>
        logQuery<ProofByHashResponse>(
          log.url,
          'ct/v1/get-proof-by-hash',
          new URLSearchParams({ hash: leafHash, tree_size: sth.tree_size.toString() }),
        ).then((resp) => logQuery<EntryResponse>(
          log.url,
          'ct/v1/get-entry-and-proof',
          new URLSearchParams({
            leaf_index: resp.leaf_index.toString(),
            tree_size: sth.tree_size.toString(),
          }),
        ))
      ).then(async (resp) => {
        const altNames = getSubjectAltNames(resp.leaf_input);
        if (!(altNames.includes(iss.host))) {
          throw new Error('issuer not in certificate altNames');
        } else if (!(altNames.includes(`${keyHash}.adem-configuration.${iss.host}`))) {
          throw new Error('key hash not in certificate altNames');
        }
      });
  }
}
