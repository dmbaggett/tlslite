"tlscrypto implementation of RC4; this just uses separated-out code from pycrypto."
try:
    import _ARC4
except ImportError:
    _ARC4 = None

if _ARC4:
    from .cryptomath import *
    from .rc4 import *

    def new(key):
        return tlscrypto_rc4(key)

    class tlscrypto_rc4(RC4):
        def __init__(self, key):
            RC4.__init__(self, key, "tlscrypto")
            key = bytes(key)
            self.context = _ARC4.new(key)

        def encrypt(self, plaintext):
            "Encrypt plaintext."
            plaintext = bytes(plaintext)
            return bytearray(self.context.encrypt(plaintext))

        def decrypt(self, ciphertext):
            "Decrypt ciphertext."
            ciphertext = bytes(ciphertext)
            return bytearray(self.context.decrypt(ciphertext))
