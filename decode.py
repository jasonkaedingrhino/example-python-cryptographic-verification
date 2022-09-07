import base64
import json
import os
import sys

import ed25519

from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey, InvalidTag, InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

assert len(sys.argv) > 1, 'Expected filename argument'

filename = sys.argv[1]

with open(filename, 'rt') as lic:
    raw_data = lic.readlines()

assert raw_data[0].rstrip() == '-----BEGIN LICENSE FILE-----', 'Expected header line'
assert raw_data[-1].rstrip() == '-----END LICENSE FILE-----', 'Expected footer line'

license_b64 = ''.join(raw_data[1:-1]).strip()
    
license_raw = json.loads( base64.b64decode(license_b64) )

print('encoding: %s' % license_raw['alg'])
encoding, alg = license_raw['alg'].split('+')

enc = license_raw['enc']
sig = license_raw['sig']

enc_bytes = ('license/%s' % enc).encode()
sig_bytes = base64.b64decode(sig)

if alg == 'ed25519':
    verify_key = ed25519.VerifyingKey(
        os.environ['KEYGEN_PUBLIC_KEY'].encode(),
        encoding='hex'
    )

    try:
        verify_key.verify(sig_bytes, enc_bytes)
    except ed25519.BadSignatureError:
        exit('!!! LICENSE NOT VALID !!!')
        
else:
    verify_key = serialization.load_pem_public_key(
        base64.b64decode(os.environ['KEYGEN_RSA_PUBLIC_KEY']),
        backend=default_backend()
    )
    
    if 'pss' in alg:
        pad = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        )
    else:
        pad = padding.PKCS1v15()

    try:
        verify_key.verify(sig_bytes, enc_bytes, pad, hashes.SHA256())
    except (InvalidSignature, TypeError):
        exit('!!! LICENSE NOT VALID !!!')

tryAESGCM = True

if encoding == 'base64':
    license_dec = str( base64.b64decode( license_raw['enc'] ), 'ascii' )
else:
    assert len(sys.argv) > 2, 'Expected license key argument'

    digest = hashes.Hash(hashes.SHA256())
    digest.update(sys.argv[2].encode())
    key = digest.finalize()

    # Split and decode
    ciphertext, iv, tag = map(
        lambda p: base64.b64decode(p),
        license_raw['enc'].split('.')
    )
    
    # Decrypt
    if tryAESGCM:
        aes = AESGCM(key)
        try:
            license_dec = aes.decrypt(iv, ciphertext + tag, None)
        except InvalidKey:
            sys.exit('!!! DECRYPTION FAILED - INVALID KEY !!!')
        except InvalidTag:
            sys.exit('!!! DECRYPTION FAILED - INVALID TAG !!!')
    else:
        try:
            aes = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, None, len(tag)),
                default_backend()
            )
            dec = aes.decryptor()

            license_dec = dec.update(ciphertext) + \
                dec.finalize_with_tag(tag)

        except InvalidKey:
            sys.exit('!!! DECRYPTION FAILED - INVALID KEY !!!')
        except InvalidTag:
            sys.exit('!!! DECRYPTION FAILED - INVALID TAG !!!')


enc = json.loads( license_dec )

print('license expiry: %s' % enc['data']['attributes']['expiry'])
print('license file expiry: %s' % enc['meta']['expiry'])

expires = datetime.strptime(enc['data']['attributes']['expiry'], '%Y-%m-%dT%H:%M:%S.%f%z')
if expires < datetime.now(timezone.utc):
    print('!!! LICENSE EXPIRED AT %s !!!' % str(expires))
    exit(1)


print('\nincluded:')
for e in enc['included']:

    print('%s %s %s' % (e['type'], e['id'], e['attributes']['name']) )

