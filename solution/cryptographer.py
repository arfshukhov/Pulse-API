import hashlib


class Cryptographer:
    def __init__(self):
        pass

    def encrypt(self, word):
        self.cryptor = hashlib.sha256()
        self.cryptor.update(bytearray(word.encode()))
        return self.cryptor.hexdigest()


crypto = Cryptographer()
