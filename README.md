# ADEM Token Verification Library

This package verifies ADEM tokens and can fetch ADEM token sets from DNS.

```ts
import { fetchDnsTokens, verifyTokens } from 'adem-chrome';

const material = await fetchDnsTokens('emblem.felixlinker.de');
const result = await verifyTokens([
  ...material.tokens,
  ...material.keys.map((key) => JSON.stringify(key)),
]);
```

Build and test the package with:

```sh
npm run build
npm test
```

Tests use static DNS fixtures and make no DNS or Certificate Transparency
requests.
