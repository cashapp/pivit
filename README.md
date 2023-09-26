# Pivit
Pivit is a command line tool for managing x509 certificates stored on smart cards with PIV applet support (Yubikey),
and using those certificates to sign and verify data.

It is fully compatible with how the `git` command line calls external programs to sign and verify commits and tags.


## Install

```shell
go install github.com/cashapp/pivit/cmd/pivit@latest
```

To set up git to use `pivit` to sign and verify signatures run the following commands:

```shell
git config --(local|global) gpg.format x509
git config --(local|global) gpg.x509.program pivit
```

## Usage

### Reset and initialize Yubikey PIV

```shell
pivit --reset
```

Reset the Yubikey's PIV applet and create a new PIN to access it.

### Generate a certificate

```shell
pivit --generate [--p256] [--self-sign | --no-csr] [--assume-yes]
```

Generate a new key pair in the Yubikey's card authentication slot.  
This command will also generate and store a x509 certificate for the generated key that's signed by Yubico.

If the option `--p256` is provided, the key pair is generated using elliptic curve P-256.
Otherwise, Curve P-384 is used.

Add the `--self-sign` flag to generate a self-signed certificate;
the certificate is signed with the newly-generated key.  
You will be prompted to confirm a self-signed certificate is really desired, 
then prompted for the PIN, and then prompted to touch your Yubikey.  
The output will contain 3 `CERTIFICATE` blocks instead of a `CERTIFICATE_REQUEST` at the end (example output below).  
**This option is useful mostly for testing purposes.**
The `--assume-yes` flag can be used in combination with the `--self-sign` option to disable its y/n prompt.

Add the `--no-csr` flag to skip the certificate signing request being printed. In this case, you will not be prompted to touch your Yubikey.  
This option is useful if you don't need the generated key to be a part of an existing PKI.  
you can still verify the key's certificate using Yubico's certificate [here](https://developers.yubico.com/PIV/Introduction/PIV_attestation.html).

Output for the command will look like:

```text
Printing Yubikey device attestation certificate:
----- BEGIN CERTIFICATE -----
...
----- END CERTIFICATE -----
Printing generated key certificate:
----- BEGIN CERTIFICATE -----
...
----- END CERTIFICATE -----
Printing certificate signing request:
----- BEGIN CERTIFICATE REQUEST -----
...
----- END CERTIFICATE REQUEST-----
```

The `CERTIFICATE REQUEST` at the end and signed by the new generated private key,
and can be used to issue a certificate signed by a CA.

If you choose to issue and use your own certificate, it's important to also verify that:

- The device attestation certificate is signed by Yubico.
- The key certificate is signed by the device attestation certificate.
- The public key in the certificate signing request is the same as the public key in the key certificate.

#### Certificate Request Parameters
Pivit allows settings different attributes in the CSR via environment variables.

The following certificate options will be set as follows:
 - `Subject.CommonName` will be set to the value of the `PIVIT_EMAIL` environment variable.
 - `Subject.Organization` will be set to the value of the `PIVIT_ORG` environment variable.
 - `Subject.OrganizationalUnit` will be set to the value of the `PIVIT_ORG_UNIT` environment variable.

Additionally, the following Subject Alternative Names (SANs) will be included in the certificate request:
 - **Email addresses** will include `PIVIT_EMAIL`
 - **URIs** will include all URLs specified in the `PIVIT_CERT_URIS` environment variable (comma separated)

#### PIV slot support

The PIV module supports multiple slots where keys and certificates can be stored.  
Available slots - `9a`, `9c`, `9d`, and `9e`.

- `9e` is the "Card Authentication" slot.  
  This is the only slot that doesn't require a PIN to access the private key when signing with it, resulting in less friction in usage.
- `9a` is the "Authentication" slot. Used for actions like system login.
- `9c` is the "Digital Signature" slot. Used for document signing, or signing files and executables.
- `9d` is the "Key Management" slot. Used for things like encrypting e-mails or files for the purpose of confidentially.

For more [information](https://developers.yubico.com/PIV/Introduction/Certificate_slots.html)

`pivit` allows choosing a slot using the `-w` flag.  
For each command, if no slot is specified, `9e` is used by default.  
For example:

- Certificate generation

  ```shell
  pivit --generate [-w slot]
  ```

- Signing

  ```shell
  pivit -s -u userid [-w slot]
  ```

- Printing a certificate

  ```shell
  pivit --print [-w slot]
  ```

### Import certificate to Yubikey

```shell
pivit --import [--first-pem] [file]
```

Imports a certificate from `file`.  
The given filename is expected to contain a serialized x509 certificate encoded as a PEM block.

This action prompts for the Yubikey PIN.

Add `--first-pem` to import the first PEM block from `file`, ignoring the rest.  This is helpful if using a CA that
provides its issued certificates as a chain or bundle, with the end-entity certificate first (this is the convention).

### Print certificate information

```shell
pivit --print
```

Prints the certificate stored in the Yubikey's card authentication slot, alongside its fingerprint.  
For example:

```bash
> pivit --print
bad126c47dc90e90e0c7ec90ec682b1717e52757
-----BEGIN CERTIFICATE-----
MIICczCCAVugAwIBAgIRANATKTxzlHOJgMdV30XRz5kwDQYJKoZIhvcNAQELBQAw
ITEfMB0GA1UEAwwWWXViaWNvIFBJViBBdHRlc3RhdGlvbjAgFw0xNjAzMTQwMDAw
MDBaGA8yMDUyMDQxNzAwMDAwMFowJTEjMCEGA1UEAwwaWXViaUtleSBQSVYgQXR0
ZXN0YXRpb24gOWUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT1l76Mvo6dJ4CwX2QQ
HImYRWbxLqt1kCVsn0PUn20DYtSKLuq8kCnMAn+kdneqjtaaBmWuPJH+g7LMyI18
QDQp2w+qSOf9ZWrOupMAGM8EpWXNTSNKoE50JhKXFbudBByjTjBMMBEGCisGAQQB
gsQKAwMEAwUBAjAUBgorBgEEAYLECgMHBAYCBACDq1IwEAYKKwYBBAGCxAoDCAQC
AQIwDwYKKwYBBAGCxAoDCQQBBDANBgkqhkiG9w0BAQsFAAOCAQEAGSmu0PUMDfEb
PkmkJ/rKYvpOKhbmpryjXuZ7ENJ3jGq3foyLSN+aBbd3M1im2ejC6/upthcp1N5M
Mg2SN6MBRS4crtt43DVHepBPt2W07vW8h4uFosJX29HdhK0dP+RnBGDdWYo0nq7y
7q1Y1c0BI7oGnaORL0DzSDtdxAJAphjspWsWNCIP2DTWQPhLTg4DqmYd/ahygVsZ
IE64QvJDQC72Dfyad6tIajmtPncqPt857H0hEJv2X58iOoJA/wAeuId4or859cJU
GTDbN7Ke4LWXRbs7StJTgefmNgWmKjm1Q2qs80WGShyQ6OrxALejd8jivtcTwsDz
WvzdmHCOmg==
-----END CERTIFICATE-----
```

The certificate's fingerprint is calculated by performing a SHA1 checksum on the raw certificate bytes
and then encoding the checksum as a hex string.

Use the certificate fingerprint to let git know which certificate to use when signing commits and tags:

```shell
FINGERPRINT=`pivit --print | head -1`
git config --(local|global) user.signingkey $FINGERPRINT
```

### Sign

```text
pivit -s [-a] [-b] [-u userid] [--status-fd=[num]] [-t url] [file]
```

* `-a` (`--armor`) - whether to wrap the signature in ASCII armor to make it printable.
* `-b` (`--detach-sign`) - make a detached signature.
* `-u` (`--local-user`) - either an email address or a key fingerprint encoded as a hex string.  
  This identifier determines which certificate to use. If an email address is supplied, look for a certificate that contains the given address.  
  If a key fingerprint is supplied, look for a certificate where its SHA1 checksum matched the given hex string.
* `--status-fd` - file descriptor to emit status messages to. `1` is stdout, `2` is stderr.  
  Any value `0` or below means no status messages will be written.
* `-t` (`--timestamp-authority`) - URL of RFC3161 timestamp authority to use for timestamping.
* `file` - path to the file that will be signed. If no filename is specified, use stdin.

This command will cause the Yubikey to flash and will block until it is touched.

When `git` is set up to sign commits and tags, it'll use the following hardcoded parameters `-sbau [user.signingkey] --status-fd=1`.  
`user.signingkey` is taken from git's local/global configuration.

### Verify signature

```shell
pivit --verify [file ...]
```

Verifies the signed data specified in the file argument(s).

If no files were specified, read from stdin.  
If one or no file paths were specified, assume the signature is attached to the signed data.

Otherwise, assume that the first file contains the signature, and the second contains the signed data.  
Specify `-` to indicate the signed data should be read from stdin.
