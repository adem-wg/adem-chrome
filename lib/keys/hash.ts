import { JWK } from "jose";

export function readKID(jwk?: JWK): string {
  if (jwk === undefined) {
    throw new Error('cannot read kid from no key');
  }

  if (jwk.kid !== undefined) {
    return jwk.kid;
  } else {
    throw new Error('no kid present');
  }
}
