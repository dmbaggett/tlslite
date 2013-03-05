"Minimal implementation of AES; this just uses separated-out code from pycrypto."

try:
    import _AES
except ImportError:
    _AES = None

if _AES:
    from .cryptomath import *
    from .aes import *

    MODES = {
        1: _AES.MODE_ECB,
        2: _AES.MODE_CBC,
        3: _AES.MODE_CFB,
        "ECB": _AES.MODE_ECB,
        "CBC": _AES.MODE_CBC,
        "CFB1": _AES.MODE_CFB,
        "ecb": _AES.MODE_ECB,
        "cbc": _AES.MODE_CBC,
        "cfb1": _AES.MODE_CFB
        }

    def new(key, mode, IV):
        return Minimal_AES(key, mode, IV)

    class Minimal_AES(AES):
        def __init__(self, key, mode, IV):
            AES.__init__(self, key, mode, IV, "minimal")
            key = bytes(key)
            IV = bytes(IV)
            self.context = _AES.new(key, MODES.get(mode, "CBC"), IV)

        def encrypt(self, plaintext):
            "Encrypt plaintext."
            plaintext = bytes(plaintext)
            return bytearray(self.context.encrypt(plaintext))

        def decrypt(self, ciphertext):
            "Decrypt ciphertext."
            ciphertext = bytes(ciphertext)
            return bytearray(self.context.decrypt(ciphertext))
