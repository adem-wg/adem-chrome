import ASN1 from '@lapo/asn1js';
import jDataView from 'jdataview';

function certGetPath(cert: any, ...is: number[]): any {
  return is.reduce((cert: any, i: number) => i < cert?.sub?.length ? cert.sub[i] : undefined, cert);
}

export function decodeLeafInput(leaf_input: string): any {
  const buf = Uint8Array.from(window.atob(leaf_input), (c) => c.charCodeAt(0));
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

export function getSubjectAltNames(leaf_input: string): string[] {
  return findSubjectAltNames(decodeLeafInput(leaf_input));
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
