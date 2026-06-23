import ASN1 from '@lapo/asn1js';
import jDataView from 'jdataview';

function certGetPath(cert: any, ...is: number[]): any {
  return is.reduce((cert: any, i: number) => i < cert?.sub?.length ? cert.sub[i] : undefined, cert);
}

export function decodeLeafInput(leaf_input: string): any {
  const buf = Buffer.from(leaf_input, 'base64');
  const view = new jDataView(buf);
  view.skip(1);  // version
  view.skip(1);  // leaf_type
  view.skip(8);  // timestamp
  view.skip(2);  // entry_type
  view.skip(32); // issuer_key_hash

  // Calculate length of tbs_certificate
  const uint32 = new Uint8Array(4);
  uint32.set(view.getBytes(3), 1); // read length field
  const tbsLength = new DataView(uint32.buffer, 0).getUint32(0, false)
  return ASN1.decode(view.getBytes(tbsLength)); // read tbs_certificate
}

export function getSubjectAltNames(cert_der: string | Buffer | any): string[] {
  return findSubjectAltNames(parseCertificateOrTbs(cert_der));
}

function parseCertificateOrTbs(cert_der: string | Buffer | any): any {
  if (!(Buffer.isBuffer(cert_der) || typeof cert_der === 'string')) {
    return cert_der;
  }

  const buf = typeof cert_der === 'string' ? Buffer.from(cert_der, 'base64') : cert_der;
  if (isLeafInput(buf)) {
    return decodeLeafInput(buf.toString('base64'));
  }

  const cert = ASN1.decode(buf);
  return certGetPath(cert, 0, 0, 0)?.content() === '2' ? certGetPath(cert, 0) : cert;
}

function isLeafInput(buf: Buffer): boolean {
  if (buf.length < 15 || buf[0] !== 0 || buf[1] !== 0) {
    return false;
  }

  const entryType = buf.readUInt16BE(10);
  const certificateLengthOffset = entryType === 0 ? 12 : entryType === 1 ? 44 : -1;
  if (certificateLengthOffset < 0 || certificateLengthOffset + 3 > buf.length) {
    return false;
  }

  const certificateLength = readUint24(buf, certificateLengthOffset);
  return certificateLengthOffset + 3 + certificateLength <= buf.length;
}

export interface StaticLogEntry {
  certificate: Buffer
  leafIndex?: number
}

function readUint24(buf: Buffer, offset: number): number {
  return buf.readUIntBE(offset, 3);
}

function readUint40(buf: Buffer, offset: number): number {
  return buf.readUIntBE(offset, 5);
}

function readOpaque(buf: Buffer, offset: number, lengthBytes: 2 | 3): [Buffer, number] {
  if (offset + lengthBytes > buf.length) {
    throw new Error('truncated static CT entry');
  }

  const length = lengthBytes === 2 ? buf.readUInt16BE(offset) : readUint24(buf, offset);
  const start = offset + lengthBytes;
  const end = start + length;
  if (end > buf.length) {
    throw new Error('truncated static CT entry');
  }
  return [buf.subarray(start, end), end];
}

function readStaticLeaf(buf: Buffer, offset: number): [StaticLogEntry, number] {
  if (offset + 10 > buf.length) {
    throw new Error('truncated static CT entry');
  }

  let pos = offset + 8; // timestamp
  const entryType = buf.readUInt16BE(pos);
  pos += 2;

  let certificate: Buffer;
  let preCertificate: Buffer | undefined;
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

function parseStaticLeafIndex(extensions: Buffer): number | undefined {
  if (extensions.length === 0) {
    return undefined;
  }

  let pos = 0;
  while (pos < extensions.length) {
    if (pos + 3 > extensions.length) {
      throw new Error('invalid static CT extensions');
    }
    const extensionType = extensions.readUInt8(pos);
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

export function getStaticEntryCertificate(tile: ArrayBuffer | Buffer, index: number): Buffer {
  const buf = Buffer.from(tile);
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
