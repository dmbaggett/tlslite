# Author: Dave Baggett (Arcode Corporation)
# See the LICENSE file for legal information regarding use of this file.

"""Abstract class for RC2."""

class RC2:
    def __init__(self, keyBytes, implementation):
        if len(keyBytes) < 5 or len(keyBytes) > 256:
            raise ValueError()
        self.isBlockCipher = False
        self.name = "rc2"
        self.implementation = implementation

    def encrypt(self, plaintext):
        raise NotImplementedError()

    def decrypt(self, ciphertext):
        raise NotImplementedError()
