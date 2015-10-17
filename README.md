# tl-create
Node command line tool to create a X.509 trust list from various trust stores

There are various organizations that produce lists of certificates that they believe should be trusted for one thing or another. The most used is the Mozilla [list](http://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1) but there are more, such as the Eurpean Union "Trust Service Providers" [list](https://ec.europa.eu/digital-agenda/en/eu-trusted-lists-certification-service-providers).

Each of these lists have their own formats, this tool parses the lists provided by these other organizations and extracts the certificates that meet the specified criteria (for "email" as an example) and produces a PEM certificate bag containing these certificates.

For example to extract the roots that are trusted for email, code and web from both the EU Trust List and the Mozilla list the command would look like this:

```
node tl-create --eutil -mozilla --for 'EMAIL_PROTECTION,CODE_SIGNING' roots.pem
```


This would produce a file that looked something like this:
```
 Country: UK
 Operator: European Commission
 Source: EUTL
 -----BEGIN CERTIFICATE-----
 ...
 ...
 -----END CERTIFICATE-----
 Operator: DigiCert, Inc
 For: email, www, code
 Source: Mozilla
 -----BEGIN CERTIFICATE-----
 ...
 ...
 -----END CERTIFICATE-----
```

Valid Mozilla trust purposes 
```
  DIGITAL_SIGNATURE
  NON_REPUDIATION
  KEY_ENCIPHERMENT
  DATA_ENCIPHERMENT
  KEY_AGREEMENT
  KEY_CERT_SIGN
  CRL_SIGN
  SERVER_AUTH
  CLIENT_AUTH
  CODE_SIGNING
  EMAIL_PROTECTION
  IPSEC_END_SYSTEM
  IPSEC_TUNNEL
  IPSEC_USER
  TIME_STAMPING
  STEP_UP_APPROVED
```

How to use
```
cd path/to/your/project/folder
git clone https://github.com/PeculiarVentures/tl-create.git
cd src
node tl-create --eutil -mozilla --for 'EMAIL_PROTECTION,CODE_SIGNING' roots.pem
```

How to verify
Copy one certificte from roots.pem in a text file. Example certificate   
```
-----BEGIN CERTIFICATE-----
MIIDkTCCAnmgAwIBAgIJAL2n5O3KZGloMA0GCSqGSIb3DQEBCwUAMFoxCzAJBgNV
BAYTAkFUMS8wLQYDVQQKEyZSdW5kZnVuayB1bmQgVGVsZWtvbSBSZWd1bGllcnVu
Z3MtR21iSDEaMBgGA1UEAxMRVHJ1c3RlZCBMaXN0IENBIDEwHhcNMTQwMTI4MTcw
MjIxWhcNMTkwMTI4MTcwMjIxWjBaMQswCQYDVQQGEwJBVDEvMC0GA1UEChMmUnVu
ZGZ1bmsgdW5kIFRlbGVrb20gUmVndWxpZXJ1bmdzLUdtYkgxGjAYBgNVBAMTEVRy
dXN0ZWQgTGlzdCBDQSAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
wg0x1RDnY0iE+m251Nex3zL2qFCJJmAtLR50XvtmIJVHF+5XeiqC7sGbxQGod2ZX
p+jw4rzB1aWVpXeVNx65JLeue0GeMp5xDtxR7piv05C6HUxiRjjgqG+PSbdX4DsN
DGH/Lg/6MFkCRT6w893iA3aXdZLYEm9IahUTGFcUa1PLAsLzr/ezie8oJMUqVRpt
sXP1YAWtfusmBCIr4TePXjCkS2vO9Vw9gnZyV5ImBEGMko2gSEoMbZtc4Yy4r391
Dm7J/hSf2GRn+xWF5g+6x4iRXKEuqyh+6CplixckivJBNZOHb2quQPNAeLBFIfLd
bN00zqelrOx1sUjWLDjEFQIDAQABo1owWDAdBgNVHQ4EFgQUsJT0MPOFfU37Ha8a
HJ6ELK/YXBkwDgYDVR0PAQH/BAQDAgEGMBYGA1UdIAQPMA0wCwYJKigADwABAQEA
MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAKbm7Uqb897Q1ci8
114MubVBswZMZ3YYs8m/O5XoYuJvZVp+wuPVaFGgZkXg+/0L7y11btNmAAeDdP8L
gKDFCDqGJwZ5TdJrq2kF82+E6WegLFgEFIIfPr70DVshQbj2jcUF8BbHssgCtzad
KsDZACdd6VO+OUm3hO9HD1Gmzx7cGRFOQQ2uvghJWp4AYsIJulhbzq2JV/XYPVHv
m8zP5XmXAIJM/EKbprCq8ERypyx+muPdJBCMsH0hHRgG4ddunvCxv0hLCZ9BSZwL
JHb+howc6cWfSMmP4ILAuPOji1HteoUwXez5dxAihWdtCWJ9MzKbRsWM+ZQ5iWbr
d2XyHw8=
-----END CERTIFICATE-----
```

Run the following command 

```
openssl x509 -in root.pem -text -inform PEM
```

This should show decoded message. 

## Bug Reporting
Please report bugs either as pull requests or as issues in the issue tracker. tl-create has a full disclosure vulnerability policy. Please do NOT attempt to report any security vulnerability in this code privately to anybody.

## TODO
* Add the Microsoft Root Program

## Related
- [CommanderJS](https://github.com/tj/commander.js)
- [PKIjs](https://pkijs.org)
