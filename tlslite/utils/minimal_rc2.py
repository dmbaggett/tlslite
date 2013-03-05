"Minimal implementation of RC2; this just uses separated-out code from pycrypto."
try:
    import _ARC2
except ImportError:
    _ARC2 = None

if _ARC2:
    from .cryptomath import *
    from .rc2 import rc2

    def new(key):
        return Minimal_RC2(key)

    class Minimal_RC2(RC2):
        def __init__(self, key):
            RC2.__init__(self, key, "minimal")
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
