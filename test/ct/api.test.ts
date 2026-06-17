import { checkInclusionStatic } from '../../lib/ct/api.js';

const leafInput = "AAAAAAGF8364ywABjQJTbIh0grw0/1TkHSumWb+Fs0Ggogr621gT3PvPKG0AA3MwggNvoAMCAQICEgSuzYO4pJyDNCzBGYCJOkgiYjANBgkqhkiG9w0BAQsFADAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5jcnlwdDELMAkGA1UEAxMCUjMwHhcNMjMwMTI3MTI1MDQ2WhcNMjMwNDI3MTI1MDQ1WjAgMR4wHAYDVQQDExVlbWJsZW0uZmVsaXhsaW5rZXIuZGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC+RNYUzdtArysDJ4RuYA37S7oc50FfpR91ZZ0LVWfcZi7t2VC/e1fqBmxzv1d3g27Sc5RlczvEhxxREQdJgDBD+fD1+nQmqB8ZxRcFsTUVL36iHyinMWzk5fDu4/GwlxH5tDlJjwK2sA+LNFGZNvEioZ4/hfS5zyjonvS5qHaE6121zqFHYQYfEKyu8m8FRW3QFNIaGx79+/Si5oF3yinSo3+DYNeCg3FgnzSxhEzdl1uwSqs5Op2K5gTfwJuHF/Q8v46l/RdDtaMSlx0B3D9nRE4pg6RrTiuFD5AdnMgLvOX53V2A0T2i7hCrCXCqX9ZQ2/GRn6BPGOD6I0kvFMPLAgMBAAGjggGnMIIBozAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPLU3UaOoEhsyyqEZH7SMWakBGH3MB8GA1UdIwQYMBaAFBQusxe3WFbLrlAJQOYfr52LFMLGMFUGCCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0cDovL3IzLm8ubGVuY3Iub3JnMCIGCCsGAQUFBzAChhZodHRwOi8vcjMuaS5sZW5jci5vcmcvMH8GA1UdEQR4MHaCFWVtYmxlbS5mZWxpeGxpbmtlci5kZYJddHJjbHFnc3Brc2ppbTU2MzVwaDJ0cGo0aXFtbWMyMzMycHJ4NXZsNXZ1dGtka3pranBzYS5hZGVtLWNvbmZpZ3VyYXRpb24uZW1ibGVtLmZlbGl4bGlua2VyLmRlMEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnAAA=";

function extractCertificateFromLeafInput(input: string): Buffer {
  const buf = Buffer.from(input, 'base64');
  const certStart = 47;
  const certLength = buf.readUIntBE(44, 3);
  return buf.subarray(certStart, certStart + certLength);
}

function uint24(n: number): Buffer {
  const buf = Buffer.alloc(3);
  buf.writeUIntBE(n, 0, 3);
  return buf;
}

function uint40(n: number): Buffer {
  const buf = Buffer.alloc(5);
  buf.writeUIntBE(n, 0, 5);
  return buf;
}

function staticLeaf(cert: Buffer, index: number): Buffer {
  const extensions = Buffer.concat([
    Buffer.from([0]),
    Buffer.from([0, 5]),
    uint40(index),
  ]);
  return Buffer.concat([
    Buffer.alloc(8),
    Buffer.from([0, 0]),
    uint24(cert.length),
    cert,
    Buffer.from([0, extensions.length]),
    extensions,
    Buffer.from([0, 0]),
  ]);
}

describe('static CT API verification', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('checks static log inclusion by leaf index', async () => {
    const index = 313;
    const tile = staticLeaf(extractCertificateFromLeafInput(leafInput), index);
    const fetchMock = jest.spyOn(global, 'fetch').mockImplementation((input) => {
      const url = input.toString();
      if (url === 'https://www.gstatic.com/ct/log_list/v3/log_list.json' ||
          url === 'https://valid.apple.com/ct/log_list/current_log_list.json') {
        return Promise.resolve(new Response(JSON.stringify({
          operators: [{
            logs: [],
            tiled_logs: [{
              log_id: 'static-log',
              monitoring_url: 'https://static.example/log',
            }],
          }],
        })));
      }

      if (url === 'https://static.example/log/checkpoint') {
        return Promise.resolve(new Response('static.example/log\n314\nAAAA\n'));
      }

      if (url === 'https://static.example/log/tile/data/001.p/58') {
        return Promise.resolve(new Response(tile));
      }

      return Promise.reject(new Error(`unexpected URL ${url}`));
    });

    await checkInclusionStatic(
      'static-log',
      index,
      new URL('https://emblem.felixlinker.de'),
      'trclqgspksjim5635ph2tpj4iqmmc2332prx5vl5vutkdkzkjpsa',
    );

    expect(fetchMock).toHaveBeenCalledWith('https://static.example/log/tile/data/001.p/58');
  });
});
