import { parseTXTRecords, verifyTokens, VerificationResult } from '../lib/index.js';
import { loadDigFixture } from './fixtures.js';

const acceptFixtureCT = async (): Promise<void> => undefined;

async function verifyFixture(name: string) {
  const material = parseTXTRecords(loadDigFixture(name));
  return verifyTokens(
    material.tokens,
    material.keys,
    [],
    { ctVerifier: acceptFixtureCT },
  );
}

describe('static deployment verification fixtures', () => {
  beforeAll(() => {
    jest.useFakeTimers().setSystemTime(new Date('2026-06-17T00:10:00Z'));
  });

  afterAll(() => jest.useRealTimers());

  test('verifies emblem.felixlinker.de', async () => {
    const material = parseTXTRecords(loadDigFixture('emblem.felixlinker.de'));
    expect(material.tokens).toHaveLength(3);
    expect(material.keys).toHaveLength(3);
    const result = await verifyFixture('emblem.felixlinker.de');
    expect(result.results).not.toContain(VerificationResult.INVALID);
    expect(result.errors).toEqual([]);
    expect(result.protected).toEqual(['[2a01:4f9:c010:d8e4::1]']);
    expect(result.issuer).toBe('https://emblem.felixlinker.de');
  });

  test('verifies emblem.redcross.org.uk', async () => {
    const material = parseTXTRecords(loadDigFixture('emblem.redcross.org.uk'));
    expect(material.tokens).toHaveLength(3);
    expect(material.keys).toHaveLength(0);
    const result = await verifyFixture('emblem.redcross.org.uk');
    expect(result.results).not.toContain(VerificationResult.INVALID);
    expect(result.errors).toEqual([]);
    expect(result.protected).toEqual(['adem.redcross.org.uk']);
    expect(result.issuer).toBe('https://redcross.org.uk');
  });

  test('verifies cyberstar.online', async () => {
    const material = parseTXTRecords(loadDigFixture('cyberstar.online'));
    expect(material.tokens).toHaveLength(2);
    expect(material.keys).toHaveLength(2);
    const result = await verifyFixture('cyberstar.online');
    expect(result.results).not.toContain(VerificationResult.INVALID);
    expect(result.errors).toEqual([]);
    expect(result.protected).toEqual([
      '[185.230.63.171]',
      '[185.230.63.107]',
      '[185.230.63.186]',
      'cyberstar.online',
    ]);
    expect(result.issuer).toBe('https://cyberstar.online');
  });

  test('accumulates token parsing errors', async () => {
    const result = await verifyTokens(['not-a-token', 'also-not-a-token']);

    expect(result.results).toEqual([VerificationResult.INVALID]);
    expect(result.errors).toHaveLength(3);
    expect(result.errors.map((err) => err.message)).toContain('token set must contain exactly one emblem');
  });

  test('keeps verified emblem result when extra tokens are invalid', async () => {
    const material = parseTXTRecords(loadDigFixture('cyberstar.online'));
    const result = await verifyTokens(
      [...material.tokens, 'not-a-token'],
      material.keys,
      [],
      { ctVerifier: acceptFixtureCT },
    );

    expect(result.results).not.toContain(VerificationResult.INVALID);
    expect(result.results).toContain(VerificationResult.SIGNED);
    expect(result.errors).toHaveLength(1);
    expect(result.protected).toEqual([
      '[185.230.63.171]',
      '[185.230.63.107]',
      '[185.230.63.186]',
      'cyberstar.online',
    ]);
  });

  test('filters invalid external endorsements from the verified claim set', async () => {
    const material = parseTXTRecords(loadDigFixture('emblem.felixlinker.de'));
    const result = await verifyTokens(
      material.tokens,
      material.keys,
      [],
      {
        ctVerifier: async (_logs, issuer) => {
          if (issuer === 'https://auth.felixlinker.de') {
            throw new Error('external CT failure');
          }
        },
      },
    );

    expect(result.results).not.toContain(VerificationResult.INVALID);
    expect(result.results).toContain(VerificationResult.SIGNED);
    expect(result.results).not.toContain(VerificationResult.ENDORSED);
    expect(result.errors.map((err) => err.message)).toContain('external CT failure');
    expect(result.endorsedBy).toEqual([]);
  });
});
