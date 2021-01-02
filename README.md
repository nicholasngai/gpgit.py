# gpgit.py

`gpgit.sh` is a Python wrapper for the [GnuPG](https://gnupg.org/) software, to
convert plaintext emails of any `Content-Type` into PGP-encrypted emails using
the PGP/MIME format, defined in [RFC 3156](https://tools.ietf.org/html/rfc3156).
It reads in a raw email file including headers from stdin and outputs the email
with rewritten headers in the `multipart/encrypted` MIME type and an encrypted
body. A public key file is passed in from the command line containing a valid
GnuPG public key used to encrypt the email. Already-encrypted emails are
detected and not re-encrypted.

Optionally, headers may also be encrypted under the [Protected Headers for
Cryptographic
E-mail](https://tools.ietf.org/id/draft-autocrypt-lamps-protected-headers-02.html)
Internet-Draft. This is disabled by default but maybe enabled using the `-p`
flag, which currently encrypts only the subject. As of now, only Thunderbird
78+ supports reading and displaying encrypted subject lines.

Python 3 is required.

## Usage

```
./gpgit.py [-p] public_key
```
