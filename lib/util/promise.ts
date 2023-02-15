export function allFulfilled<T>(ps: Promise<T>[], log?: (reason: any) => void): Promise<T[]> {
  return Promise.allSettled(ps)
    .then((rs) => {
      if (log !== undefined) {
        rs.forEach((r) => {
          if (r.status === 'rejected') {
            log(r.reason);
          }
        });
      }
      return rs.filter((r) => r.status === 'fulfilled')
        .map((r) => (r as PromiseFulfilledResult<T>).value)
    });
}

export function logAndReject<T>(p: Promise<T>, log: (reason: any) => void): Promise<T> {
  return p.then((v) => v, (reason) => {
    log(reason);
    return Promise.reject(reason);
  });
}
