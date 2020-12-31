import argparse
import copy
import email
import email.encoders
import email.message
from email.mime.application import MIMEApplication
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
import errno
import io
import random
import shutil
import subprocess
import sys
from typing import Optional

ENCRYPTED_MIME_TYPES = {
    'multipart/encrypted',
    'application/pkcs7-mime',
}

def is_encrypted(message: email.message.Message) -> bool:
    if message.get_content_type() in ENCRYPTED_MIME_TYPES:
        return True
    return False

def encrypt_payload(data: str, public_key_path: str) -> str:
    gpg = subprocess.run(('gpg', '--batch', '--quiet', '--no-options',
                          '--armor', '--encrypt',
                          '--recipient-file', public_key_path),
                         input=data, encoding='utf-8', capture_output=True)
    return gpg.stdout

def encrypt_message(message: email.message.Message,
                    public_key_path: str) -> email.message.Message:
    # Skip messsages that are already encrypted.
    if is_encrypted(message):
        return message

    # PGP version part.
    version_data = 'Version: 1'
    version = MIMEApplication(version_data, 'pgp-encrypted',
                              email.encoders.encode_noop)

    # Plaintext payload part.
    payload_data = message.get_payload()
    payload = MIMEBase(message.get_content_maintype(),
                       message.get_content_subtype())
    payload['Content-Transfer-Encoding'] = message['Content-Transfer-Encoding']
    payload['Content-Disposition'] = message['Content-Disposition']
    payload.set_payload(payload_data)

    # Encrypted payload part.
    encrypted_payload_data = encrypt_payload(
            protected_headers.as_string(maxheaderlen=80),
            public_key_path)
    encrypted_payload = MIMEApplication(encrypted_payload_data, 'octet-stream',
                                        email.encoders.encode_noop,
                                        name='encrypted.asc')
    encrypted_payload.add_header('Content-Disposition', 'inline',
                                 filename='encrypted.asc')

    # Output.
    ret = MIMEMultipart('encrypted', protocol='application/pgp-encrypted')
    ret.attach(version)
    ret.attach(encrypted_payload)
    for header, value in message.items():
        if header not in ret:
            ret.add_header(header, value)

    return ret

def main(args: argparse.Namespace) -> int:
    public_key_path: str = args.public_key

    # Check if gpg is in the PATH.
    if shutil.which('gpg') is None:
        print('gpg was not found in PATH! Exiting...', file=sys.stderr)
        return errno.ENOENT

    # Read raw from stdin.
    raw = sys.stdin.read()

    # Parse message.
    message = email.message_from_string(raw)

    # Encrypt message.
    message = encrypt_message(message, public_key_path)

    # Output to stdout.
    sys.stdout.write(message.as_string(maxheaderlen=80))

    return 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('public_key', help='Public key to encrypt emails with')
    exit(main(parser.parse_args()))
