"tlscrypto implementation of RC2; this just uses separated-out code from pycrypto."
try:
    from tlscrypto import _ARC2
except ImportError:
    _ARC2 = None

if _ARC2:
    from .cryptomath import *
    from .rc2 import RC2

    def new(key):
        return tlscrypto_rc2(key)

    class tlscrypto_rc2(RC2):
        def __init__(self, key):
            RC2.__init__(self, key, "tlscrypto")
            key = bytes(key)
            self.context = _ARC2.new(key)

        def encrypt(self, plaintext):
            "Encrypt plaintext."
            plaintext = bytes(plaintext)
            return bytearray(self.context.encrypt(plaintext))

        def decrypt(self, ciphertext):
            "Decrypt ciphertext."
            ciphertext = bytes(ciphertext)
            return bytearray(self.context.decrypt(ciphertext))
