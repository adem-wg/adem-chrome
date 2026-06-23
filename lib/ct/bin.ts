import ASN1 from '@lapo/asn1js';
import { toUint8Array, readUint24, readUint40, readUint16, readUint, readOpaque } from '../util/bytes.js';

function certGetPath(cert: any, ...is: number[]): any {
  return is.reduce((cert: any, i: number) => i < cert?.sub?.length ? cert.sub[i] : undefined, cert);
}

export function decodeLeafInput(leaf_input: string | Uint8Array | ArrayBuffer): any {
  const buf = toUint8Array(leaf_input);
  let certificateOffset = 1   // version
                        + 1   // leaf_type
                        + 8   // timestamp
                        + 2   // entry_type
                        + 32; // issuer_key_hash
  const tbsLength = readUint24(buf, certificateOffset);
  certificateOffset += 3; // tbs_length
  const certificateEnd = certificateOffset + tbsLength;
  if (certificateEnd > buf.length) {
    throw new Error('truncated CT leaf input');
  }
  return ASN1.decode(buf.subarray(certificateOffset, certificateEnd));
}

export function getSubjectAltNames(cert_der: unknown): string[] {
  return findSubjectAltNames(parseCertificateOrTbs(cert_der));
}

function parseCertificateOrTbs(cert_der: unknown): any {
  try {
    const buf = toUint8Array(cert_der);
    if (isLeafInput(buf)) {
      return decodeLeafInput(buf);
    } else {
      const cert = ASN1.decode(buf);
      return certGetPath(cert, 0, 0, 0)?.content() === '2' ? certGetPath(cert, 0) : cert;
    }
  } catch (err) {
    // TODO: Is this the right error handling?
    return cert_der;
  }
}

function isLeafInput(buf: Uint8Array): boolean {
  if (buf.length < 15 || buf[0] !== 0 || buf[1] !== 0) {
    return false;
  }

  const entryType = readUint16(buf, 10);
  const certificateLengthOffset = entryType === 0 ? 12 : entryType === 1 ? 44 : -1;
  if (certificateLengthOffset < 0 || certificateLengthOffset + 3 > buf.length) {
    return false;
  }

  const certificateLength = readUint24(buf, certificateLengthOffset);
  return certificateLengthOffset + 3 + certificateLength <= buf.length;
}

export interface StaticLogEntry {
  certificate: Uint8Array
  leafIndex?: number
}

function readStaticLeaf(buf: Uint8Array, offset: number): [StaticLogEntry, number] {
  if (offset + 10 > buf.length) {
    throw new Error('truncated static CT entry');
  }

  let pos = offset + 8; // timestamp
  const entryType = readUint16(buf, pos);
  pos += 2;

  let certificate: Uint8Array;
  let preCertificate: Uint8Array | undefined;
  if (entryType === 0) {
    [certificate, pos] = readOpaque(buf, pos, 3);
  } else if (entryType === 1) {
    pos += 32; // issuer_key_hash
    [certificate, pos] = readOpaque(buf, pos, 3);
  } else {
    throw new Error(`unsupported static CT entry type ${entryType}`);
  }

  const [extensions, afterExtensions] = readOpaque(buf, pos, 2);
  pos = afterExtensions;

  if (entryType === 1) {
    [preCertificate, pos] = readOpaque(buf, pos, 3);
  }

  const [fingerprints, afterFingerprints] = readOpaque(buf, pos, 2);
  pos = afterFingerprints;

  if (fingerprints.length % 32 !== 0) {
    throw new Error('invalid static CT chain fingerprints');
  }

  return [{
    certificate: preCertificate || certificate,
    leafIndex: parseStaticLeafIndex(extensions),
  }, pos];
}

function parseStaticLeafIndex(extensions: Uint8Array): number | undefined {
  if (extensions.length === 0) {
    return undefined;
  }

  let pos = 0;
  while (pos < extensions.length) {
    if (pos + 3 > extensions.length) {
      throw new Error('invalid static CT extensions');
    }
    const extensionType = extensions[pos];
    const [extension, afterExtension] = readOpaque(extensions, pos + 1, 2);
    pos = afterExtension;

    if (extensionType === 0) {
      if (extension.length !== 5) {
        throw new Error('invalid static CT leaf index extension');
      }
      return readUint40(extension, 0);
    }
  }

  return undefined;
}

export function getStaticEntryCertificate(tile: ArrayBuffer | Uint8Array, index: number): Uint8Array {
  const buf = tile instanceof Uint8Array ? tile : new Uint8Array(tile);
  let pos = 0;
  while (pos < buf.length) {
    const [entry, next] = readStaticLeaf(buf, pos);
    if (entry.leafIndex === index) {
      return entry.certificate;
    }
    pos = next;
  }

  throw new Error(`static CT entry ${index} not found in tile`);
}

function findSubjectAltNames(cert: any): string[] {
  if (certGetPath(cert, 0, 0)?.content() !== '2') {
    return [];
  }

  // Extensions could be stored at any of these indices
  let altNames: string[] = [];
  // These indices come from https://www.rfc-editor.org/rfc/rfc5280#section-4.1
  for (const i of [7,8,9]) {
    const field = certGetPath(cert, i);
    // field with tag number 3 are the x509 extensions
    if (field?.tag.tagNumber === 3) {
      for (const seq of certGetPath(field, 0).sub) {
        const [ident, value] = seq.sub;
        // Search for right extension field...
        if (ident.content() === '2.5.29.17\nsubjectAltName\nX.509 extension') {
          for(const sub of certGetPath(value, 0).sub) {
            const [_, altName] = sub.content().split('\n');
            altNames.push(altName);
          }
        }
      }
    }
  }
  return altNames;
}
