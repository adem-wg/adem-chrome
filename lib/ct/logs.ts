const GOOGLE = "https://www.gstatic.com/ct/log_list/v3/log_list.json";
const APPLE = "https://valid.apple.com/ct/log_list/current_log_list.json";

export interface LogInfo {
  log_id: string
  url: string
}

interface Operator {
  logs: LogInfo[]
}

interface LogList {
  operators: Operator[]
}

export type LogMap = { [key: string]: LogInfo };

function fetchLog(logUrl: string): Promise<LogMap> {
  return fetch(logUrl)
    .then((response) => {
      return response.ok ? response.json() : Promise.reject();
    })
    .then((json: LogList) => {
      let logs = json.operators.map(operator => operator.logs)
        .reduce((aggr, logs) => aggr.concat(logs), []);
      return Object.fromEntries(logs.map(logInfo => [logInfo.log_id, logInfo]));
    });
}

export function fetchAllLogs(): Promise<LogMap> {
  return Promise.all([fetchLog(GOOGLE), fetchLog(APPLE)])
    .then(([google, apple]) => Object.assign(google, apple));
}
