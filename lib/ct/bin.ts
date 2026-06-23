import {
  BaseBlock,
  ObjectIdentifier,
  OctetString,
  fromBER,
  type AsnType,
} from 'asn1js';
import { readUint40, readUint16, readOpaque, decodeBase64 } from '../util/bytes.js';

const SUBJECT_ALT_NAME_OID = '2.5.29.17';
const CONTEXT_SPECIFIC_TAG_CLASS = 3;
const DNS_NAME_TAG_NUMBER = 2;
const textDecoder = new TextDecoder();

export interface CertificateEntry {
  type: 'certificate'
  certificate: Uint8Array
}

export interface PrecertificateEntry {
  type: 'precertificate'
  certificate: Uint8Array
}

function readTimestampedEntry(buf: Uint8Array, offset: number): [CertificateEntry | PrecertificateEntry, number] {
  let pos = offset + 8; // skip timestamps
  let entryType: number;
  [entryType, pos] = readUint16(buf, pos);

  let signedEntry: CertificateEntry | PrecertificateEntry;
  if (entryType === 0) {
    let certificate: Uint8Array;
    [certificate, pos] = readOpaque(buf, pos, 3);
    signedEntry = { type: 'certificate', certificate };
  } else if (entryType === 1) {
    pos = pos + 32; // skip issuer key hash
    if (pos > buf.length) {
      throw new Error('truncated CT issuer key hash');
    }

    let certificate: Uint8Array;
    [certificate, pos] = readOpaque(buf, pos, 3);
    signedEntry = { type: 'precertificate', certificate };
  } else {
    throw new Error(`unsupported CT entry type ${entryType}`);
  }

  let extensions: Uint8Array;
  [extensions, pos] = readOpaque(buf, pos, 2);
  return [signedEntry, pos];
}

export function decodeMerkleTreeLeaf(leafInput: string): CertificateEntry | PrecertificateEntry {
  const buf = decodeBase64(leafInput);
  if (buf.length < 2 || buf[0] !== 0) {
    throw new Error('unsupported CT leaf version');
  } else if (buf[1] !== 0) {
    throw new Error(`unsupported CT leaf type ${buf[1]}`);
  }

  const [ cert, end] = readTimestampedEntry(buf, 2);
  if (end !== buf.length) {
    throw new Error('trailing data in CT leaf input');
  }
  return cert;
}

export function getSubjectAltNames(cert_der: Uint8Array): string[] {
  return findSubjectAltNames(decodeAsn1(cert_der));
}

function decodeAsn1(buf: Uint8Array): AsnType {
  const decoded = fromBER(buf);
  if (decoded.offset === -1 || decoded.offset !== buf.length) {
    throw new Error(decoded.result.error || 'invalid ASN.1 data');
  }
  return decoded.result;
}

function readTileLeaf(buf: Uint8Array, offset: number): [CertificateEntry | PrecertificateEntry, number] {
  const [cert, afterTimestampedEntry] = readTimestampedEntry(buf, offset);
  let pos = afterTimestampedEntry;

  if (cert.type === 'precertificate') {
    [, pos] = readOpaque(buf, pos, 3);
  }
  [, pos] = readOpaque(buf, pos, 2);

  return [cert, pos];
}

export function getTileLeafCert(tile: Uint8Array, index: number): CertificateEntry | PrecertificateEntry {
  let pos = 0;
  const tileLeafIndex = index % 256;
  for (let i = 0; i <= tileLeafIndex && pos < tile.length; i++) {
    const [cert, next] = readTileLeaf(tile, pos);
    if (i == tileLeafIndex) {
      return cert;
    } else {
      pos = next;
    }
  }

  throw new Error(`static CT entry ${index} not found in tile`);
}

function getChildren(node: AsnType): AsnType[] {
  const valueBlock = node.valueBlock as { value?: unknown } | undefined;
  return Array.isArray(valueBlock?.value)
    ? valueBlock.value.filter((val) => val instanceof BaseBlock)
    : [];
}

function getSubjectAltNameValues(node: AsnType): OctetString[] {
  const children = getChildren(node);
  const values: OctetString[] = [];

  if (children[0] instanceof ObjectIdentifier
      && children[0].getValue() === SUBJECT_ALT_NAME_OID) {
    const value = children.find((child) => child instanceof OctetString);
    if (value instanceof OctetString) {
      values.push(value);
    }
  }

  for (const child of children) {
    values.push(...getSubjectAltNameValues(child));
  }
  return values;
}

function findSubjectAltNames(cert: AsnType | undefined): string[] {
  if (!cert) {
    return [];
  }

  const altNames: string[] = [];
  for (const extension of getSubjectAltNameValues(cert)) {
    const generalNames = decodeAsn1(new Uint8Array(extension.getValue()));
    for (const name of getChildren(generalNames)) {
      if (name.idBlock.tagClass === CONTEXT_SPECIFIC_TAG_CLASS
          && name.idBlock.tagNumber === DNS_NAME_TAG_NUMBER) {
        const valueBlock = name.valueBlock as { valueHexView?: Uint8Array };
        if (valueBlock.valueHexView) {
          altNames.push(textDecoder.decode(valueBlock.valueHexView));
        }
      }
    }
  }
  return altNames;
}
