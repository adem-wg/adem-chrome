import { decodeLeafInput, getSubjectAltNames } from '../../lib/ct/bin';

const leafInput = "AAAAAAGF8364ywABjQJTbIh0grw0/1TkHSumWb+Fs0Ggogr621gT3PvPKG0AA3MwggNvoAMCAQICEgSuzYO4pJyDNCzBGYCJOkgiYjANBgkqhkiG9w0BAQsFADAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5jcnlwdDELMAkGA1UEAxMCUjMwHhcNMjMwMTI3MTI1MDQ2WhcNMjMwNDI3MTI1MDQ1WjAgMR4wHAYDVQQDExVlbWJsZW0uZmVsaXhsaW5rZXIuZGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC+RNYUzdtArysDJ4RuYA37S7oc50FfpR91ZZ0LVWfcZi7t2VC/e1fqBmxzv1d3g27Sc5RlczvEhxxREQdJgDBD+fD1+nQmqB8ZxRcFsTUVL36iHyinMWzk5fDu4/GwlxH5tDlJjwK2sA+LNFGZNvEioZ4/hfS5zyjonvS5qHaE6121zqFHYQYfEKyu8m8FRW3QFNIaGx79+/Si5oF3yinSo3+DYNeCg3FgnzSxhEzdl1uwSqs5Op2K5gTfwJuHF/Q8v46l/RdDtaMSlx0B3D9nRE4pg6RrTiuFD5AdnMgLvOX53V2A0T2i7hCrCXCqX9ZQ2/GRn6BPGOD6I0kvFMPLAgMBAAGjggGnMIIBozAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPLU3UaOoEhsyyqEZH7SMWakBGH3MB8GA1UdIwQYMBaAFBQusxe3WFbLrlAJQOYfr52LFMLGMFUGCCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0cDovL3IzLm8ubGVuY3Iub3JnMCIGCCsGAQUFBzAChhZodHRwOi8vcjMuaS5sZW5jci5vcmcvMH8GA1UdEQR4MHaCFWVtYmxlbS5mZWxpeGxpbmtlci5kZYJddHJjbHFnc3Brc2ppbTU2MzVwaDJ0cGo0aXFtbWMyMzMycHJ4NXZsNXZ1dGtka3pranBzYS5hZGVtLWNvbmZpZ3VyYXRpb24uZW1ibGVtLmZlbGl4bGlua2VyLmRlMEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnAAA=";
const altNames = ['emblem.felixlinker.de', 'trclqgspksjim5635ph2tpj4iqmmc2332prx5vl5vutkdkzkjpsa.adem-configuration.emblem.felixlinker.de'];

describe('Can parse get-entry-and-proof response', () => {
  test('Can parse leaf_input', () => {
    const parsed = decodeLeafInput(leafInput);
    expect(parsed).toBeDefined();
  });

  test('Can find subject alt names', () => {
    const found = getSubjectAltNames(leafInput);
    for (const altName of altNames) {
      expect(found).toContain(altName);
    }
  });
});
