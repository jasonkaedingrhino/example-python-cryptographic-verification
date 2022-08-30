import base64
from datetime import datetime, timezone
import json
import os
import sys

import ed25519

assert len(sys.argv) > 1, 'Expected filename argument'

filename = sys.argv[1]

with open(filename, 'rt') as lic:
    raw_data = lic.readlines()

assert raw_data[0].rstrip() == '-----BEGIN LICENSE FILE-----', 'Expected header line'
assert raw_data[-1].rstrip() == '-----END LICENSE FILE-----', 'Expected footer line'

license_b64 = ''.join(raw_data[1:-1]).strip()
    
license_raw = json.loads( str( base64.b64decode(license_b64), 'ascii' ) )

print('encoding: %s' % license_raw['alg'])
assert 'ed25519' in license_raw['alg'], '!!! NOT ED25519 !!!'

enc = license_raw['enc']
sig = license_raw['sig']

enc_bytes = ('license/%s' % enc).encode()
sig_bytes = base64.b64decode(sig)

verify_key = ed25519.VerifyingKey(os.environ['KEYGEN_PUBLIC_KEY'].encode(), encoding='hex')

try:
    verify_key.verify(sig_bytes, enc_bytes)
except ed25519.BadSignatureError:
    print('!!! LICENSE NOT VALID !!!')
    exit(1)

enc = json.loads( str( base64.b64decode( license_raw['enc'] ), 'ascii' ) )

print('license expiry: %s' % enc['data']['attributes']['expiry'])
print('license file expiry: %s' % enc['meta']['expiry'])

expires = datetime.strptime(enc['data']['attributes']['expiry'], '%Y-%m-%dT%H:%M:%S.%f%z')
if expires < datetime.now(timezone.utc):
    print('!!! LICENSE EXPIRED AT %s !!!' % str(expires))
    exit(1)


print('\nincluded:')
for e in enc['included']:

    print('%s %s %s' % (e['type'], e['id'], e['attributes']['name']) )

