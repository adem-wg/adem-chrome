import { base64, base64url } from 'rfc4648';

const utf8Decoder = new TextDecoder();

export function decodeBase64(value: string): Uint8Array {
  return base64.parse(value, { loose: true });
}

export function decodeBase64Url(value: string): Uint8Array {
  return base64url.parse(value, { loose: true });
}

export function decodeBase64UrlText(value: string): string {
  return utf8Decoder.decode(decodeBase64Url(value));
}

export function readUint(buf: Uint8Array, offset: number, length: number): [number, number] {
  if (offset < 0 || length < 0 || offset + length > buf.length) {
    throw new Error('truncated binary data');
  }

  let value = 0;
  for (let i = 0; i < length; i += 1) {
    value = value * 256 + buf[offset + i];
  }
  return [value, offset+length];
}

export function readUint16(buf: Uint8Array, offset: number): [number, number] {
  return readUint(buf, offset, 2);
}

export function readUint24(buf: Uint8Array, offset: number): [number, number] {
  return readUint(buf, offset, 3);
}

export function readUint40(buf: Uint8Array, offset: number): [number, number] {
  return readUint(buf, offset, 5);
}

export function readOpaque(buf: Uint8Array, offset: number, lengthBytes: 2 | 3): [Uint8Array, number] {
  if (offset + lengthBytes > buf.length) {
    throw new Error('truncated static CT entry');
  }

  const [length, start] = readUint(buf, offset, lengthBytes);
  const end = start + length;
  if (end > buf.length) {
    throw new Error('truncated static CT entry');
  }
  return [buf.subarray(start, end), end];
}
