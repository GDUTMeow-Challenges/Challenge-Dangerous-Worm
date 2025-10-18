import os

class Global:
    def __init__(self, SECRET_PATH):
        self._ = 0x66
        self.IV = b"\x34\x55\x2b\x55\x0b\x04\x03\x14\x12\x09\x33\x16\x22\x26\x12\x23"
        if os.path.exists(SECRET_PATH):
            with open(SECRET_PATH, "rb") as f:
                self.KEY = f.read(16)
        else:
            os.makedirs(os.path.dirname(SECRET_PATH), exist_ok=True)
            with open(SECRET_PATH, "wb") as f:
                self.KEY = os.urandom(16)
                f.write(self.KEY)