"Simple implementation of RC4; this just uses separated-out code from pycrypto."
try:
    import _ARC4
except ImportError:
    _ARC4 = None

if _ARC4:
    from .cryptomath import *
    from .rc4 import *

    def new(key):
        return Simple_RC4(key)

    class Simple_RC4(RC4):
        def __init__(self, key):
            RC4.__init__(self, key, "simple")
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
