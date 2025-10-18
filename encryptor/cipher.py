from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from encryptor.vars import Global

def encrypt(data: bytes, params: Global) -> bytes:
    cipher: AES.Cb = AES.new(params.KEY, AES.MODE_CBC, bytes([b ^ params._ for b in params.IV]))
    cipher_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher_bytes

