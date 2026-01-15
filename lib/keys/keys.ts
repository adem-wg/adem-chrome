const keys: { [kid: string]: boolean } = {};

export function isAuthenticated(kid: string): Promise<void> {
  if (kid in keys) {
    return Promise.resolve();
  } else {
    return Promise.reject(new Error(`no key with kid ${kid}`));
  }
}

export function put(kid: string) {
  keys[kid] = true;
}
