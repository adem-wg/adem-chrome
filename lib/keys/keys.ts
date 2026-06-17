import { JWK } from 'jose';
import { calculateKid } from './hash.js';

export class KeyStore {
  private keys: { [kid: string]: JWK } = {};
  private authenticated: { [kid: string]: boolean } = {};

  async add(key: JWK): Promise<string> {
    const kid = await calculateKid(key);
    this.keys[kid] = Object.assign({}, key, { kid });
    return kid;
  }

  get(kid: string): JWK | undefined {
    return this.keys[kid];
  }

  isAuthenticated(kid: string): Promise<void> {
    if (kid in this.authenticated) {
      return Promise.resolve();
    }
    return Promise.reject(new Error(`no key with kid ${kid}`));
  }

  put(kid: string): void {
    this.authenticated[kid] = true;
  }
}
