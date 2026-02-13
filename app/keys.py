from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import time
import base64

class KeyManager:
    def __init__(self):
        self.keys = {}
        self._init_keys()
    
    def _init_keys(self):
        # Active key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.keys['active-1'] = {
            'private': private_key,
            'expires_at': int(time.time()) + 3600,
            'kid': 'active-1'
        }
        # Expired key
        private_key_exp = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.keys['expired-1'] = {
            'private': private_key_exp,
            'expires_at': int(time.time()) - 3600,
            'kid': 'expired-1'
        }
    
    def get_unexpired_jwks(self):
        now = int(time.time())
        jwks_keys = []
        for kid, key_data in self.keys.items():
            if key_data['expires_at'] > now:
                public_numbers = key_data['private'].public_key().public_numbers()
                n = base64.urlsafe_b64encode(
                    public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')
                ).decode('utf-8').rstrip('=')
                e = base64.urlsafe_b64encode(
                    public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')
                ).decode('utf-8').rstrip('=')
                
                jwks_keys.append({
                    'kid': kid,
                    'kty': 'RSA',
                    'n': n,
                    'e': e,
                    'alg': 'RS256',
                    'use': 'sig'
                })
        return {'keys': jwks_keys}
    
    def get_key(self, kid):
        return self.keys.get(kid)

key_manager = KeyManager()
