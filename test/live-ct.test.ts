import { parseTXTRecords, verifyTokens, VerificationResult } from '../lib/index.js';
import { loadDigFixture } from './fixtures.js';

const runLiveCtTests = process.env.ADEM_LIVE_CT_TESTS === '1';
const describeLiveCt = runLiveCtTests ? describe : describe.skip;

jest.setTimeout(60000);

function loadStoredTokens(name: string): string[] {
  const material = parseTXTRecords(loadDigFixture(name));
  return [
    ...material.tokens,
    ...material.keys.map((key) => JSON.stringify(key)),
  ];
}

async function verifyStoredTokensWithLiveCt(name: string) {
  return verifyTokens(loadStoredTokens(name));
}

describeLiveCt('live CT API verification fixtures', () => {
  let fetchSpy: jest.SpiedFunction<typeof fetch>;

  beforeAll(() => {
    jest.useFakeTimers().setSystemTime(new Date('2026-06-17T00:10:00Z'));

    const realFetch = global.fetch;
    fetchSpy = jest.spyOn(global, 'fetch').mockImplementation((input, init) => {
      const url = typeof input === 'string' || input instanceof URL ? input.toString() : input.url;
      if (url.startsWith('https://dns.google.com/resolve')) {
        throw new Error(`live CT tests must use stored tokens, not DNS queries: ${url}`);
      }
      return realFetch.call(global, input, init);
    });
  });

  afterAll(() => {
    fetchSpy.mockRestore();
    jest.useRealTimers();
  });

  test.each([
    ['emblem.felixlinker.de', ['[2a01:4f9:c010:d8e4::1]'], 'https://emblem.felixlinker.de'],
    ['emblem.redcross.org.uk', ['adem.redcross.org.uk'], 'https://redcross.org.uk'],
    [
      'cyberstar.online',
      ['[185.230.63.171]', '[185.230.63.107]', '[185.230.63.186]', 'cyberstar.online'],
      'https://cyberstar.online',
    ],
  ])('verifies %s using real CT API calls', async (fixture, protectedAssets, issuer) => {
    const result = await verifyStoredTokensWithLiveCt(fixture);
    expect(result.errors).toEqual([]);
    expect(result.results).not.toContain(VerificationResult.INVALID);
    expect(result.protected).toEqual(protectedAssets);
    expect(result.issuer).toBe(issuer);
  });
});
