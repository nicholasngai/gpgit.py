#!/usr/bin/env python3

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
import secrets
import shutil
import subprocess
import sys
from typing import Optional

import gpg

ENCRYPTED_MIME_TYPES = {
    'multipart/encrypted',
    'application/pkcs7-mime',
}

def is_encrypted(message: email.message.Message) -> bool:
    return message.get_content_type() in ENCRYPTED_MIME_TYPES

def encrypt_payload(data: str, public_key_path: str) -> str:
    with gpg.Context(armor=True) as c:
        out_data = gpg.Data()
        c.op_encrypt_ext([], '--file\n' + public_key_path,
                         gpg.constants.ENCRYPT_ALWAYS_TRUST,
                         data.encode('utf-8'), out_data)
        result = c.op_encrypt_result()
        if result.invalid_recipients:
            raise gpg.errors.InvalidRecipients(result.invalid_recipients)
        out_data.seek(0)
        return out_data.read().decode('utf-8')

def generate_boundary() -> str:
    return f'gpgit-v1-{secrets.token_hex(16)}'

def encrypt_message(message: email.message.Message, public_key_path: str,
                    protect_headers: bool) -> email.message.Message:
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
                       message.get_content_subtype(),
                       **dict((message.get_params() or ('text/plain',))[1:]))
    for header, value in message.items():
        lower = header.lower()
        if lower.startswith('content-') and lower != 'content-type':
            payload[header] = value
    if 'Content-Transfer-Encoding' not in payload:
        payload['Content-Transfer-Encoding'] = '7bit'
    payload.set_payload(payload_data)

    if protect_headers:
        # Protected headers MIME wrapper.
        if payload.is_multipart():
            protected_headers = payload
        else:
            protected_headers = MIMEMultipart('mixed')
            protected_headers.attach(payload)
        protected_headers.set_param('protected-headers', 'v1')
        if 'Subject' in message:
            protected_headers['Subject'] = message['Subject']
        payload = protected_headers

    # Encrypted payload part.
    encrypted_payload_data = encrypt_payload(
            payload.as_string(maxheaderlen=80),
            public_key_path)
    encrypted_payload = MIMEApplication(encrypted_payload_data, 'octet-stream',
                                        email.encoders.encode_noop,
                                        name='encrypted.asc')
    encrypted_payload.add_header('Content-Disposition', 'inline',
                                 filename='encrypted.asc')

    # Output.
    ret = MIMEMultipart('encrypted', protocol='application/pgp-encrypted', boundary=generate_boundary())
    ret.attach(version)
    ret.attach(encrypted_payload)
    for header, value in message.items():
        if protect_headers and header.lower() == 'subject':
            ret[header] = '...'
        elif header not in ret and not header.lower().startswith('content-'):
            ret[header] = value

    return ret

def main(args: argparse.Namespace) -> int:
    public_key_path: str = args.public_key
    protect_headers: bool = args.protect_headers

    # Check if gpg is in the PATH.
    if shutil.which('gpg') is None:
        print('gpg was not found in PATH! Exiting...', file=sys.stderr)
        return errno.ENOENT

    # Read raw from stdin.
    raw = sys.stdin.read()

    # Parse message.
    message = email.message_from_string(raw)

    # Encrypt message.
    message = encrypt_message(message, public_key_path, protect_headers)

    # Output to stdout.
    sys.stdout.write(message.as_string(maxheaderlen=80))

    return 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('public_key', help='Public key to encrypt emails with')
    parser.add_argument('-p', '--protect-headers', action='store_true',
                        help='Enable protected headers')
    exit(main(parser.parse_args()))
