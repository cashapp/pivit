# Pivit
Pivit is a command line tool for managing x509 certificates stored on smart cards with PIV applet support (Yubikey),
and using those certificates to sign and verify data.

It is fully compatible with how the `git` command line calls external programs to sign and verify commits and tags.

# Install
```
go install github.com/cashapp/pivit/cmd/pivit@latest
```

To set up git to use `pivit` to sign and verify signatures run the following commands:
```
git config --(local|global) gpg.format x509
git config --(local|global) gpg.x509.program pivit
```

# Usage

## Reset and initialize Yubikey PIV
```
pivit --reset
```

Reset the Yubikey's PIV applet and create a new PIN to access it.

## Generate a certificate
```
pivit --generate
```
Generate a new key pair in the Yubikey's card authentication slot.  
This command will also generate and store a x509 certificate for the generated key that's signed by Yubico.

Output for the command will look like:
```
Printing Yubikey device attestation certificate:
----- CERTIFICATE -----
...
----- END CERTIFICATE -----
Printing generated key certificate:
----- CERTIFICATE -----
...
----- END CERTIFICATE -----
Printing certificate signing request:
----- CERTIFICATE REQUEST -----
...
----- END CERTIFICATE REQUEST-----
```

The `CERTIFICATE REQUEST` at the end and signed by the new generated private key,
and can be used to issue a certificate signed by a CA.

If you choose to issue and use your own certificate, it's important to also verify that:
 - The device attestation certificate is signed by Yubico.
 - The key certificate is signed by the device attestation certificate.
 - The public key in the certificate signing request is the same as the public key in the key certificate.

You can set the organization name, organization unit, and email address in the certificate request's subject
by setting the `PIVIT_ORG`, `PIVIT_ORG_UNIT`, and `PIVIT_EMAIL` environment variables before executing this command.

### To Use A Different Slot to Generate a Certificate
```
pivit --generate -w [slot]
```

Available slots - 9a, 9c, 9d. Defaults to slot 9e.

 9e is the "Card Authentication" slot. This is the only slot that doesn't require a PIN to access the private key when signing with it. Resulting in less friction in usage.

 9a is the "Authentication" slot. This slot is used for actions like system login.

 9c is the "Digital Signature" slot. This slot is used for document signing, or signing files and executables

 9d is the "Key Management" slot. This slot is used for things like encrypting e-mails or files for the purpose of confidentially.

 For more information: https://developers.yubico.com/PIV/Introduction/Certificate_slots.html

## Import certificate to Yubikey
```
pivit --import --cert-file [file]
```

Imports a certificate from `file`.  
The given filename is expected to contain a serialized x509 certificate encoded as a PEM block.

This action prompts for the Yubikey PIN.

## Print certificate information
```
pivit --print
```

Prints the certificate stored in the Yubikey's card authentication slot, alongside its fingerprint.  
For example:
```
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
```
FINGERPRINT=`pivit --print | head -1`
git config --(local|global) user.signingkey $FINGERPRINT
```

## Sign
```
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

## Verify signature
```
pivit --verify [file ...]
```

Verifies the signed data specified in the file argument(s).

If no files were specified, read from stdin.  
If one or no file paths were specified, assume the signature is attached to the signed data.

Otherwise, assume that the first file contains the signature, and the second contains the signed data.  
Specify `-` to indicate the signed data should be read from stdin.
