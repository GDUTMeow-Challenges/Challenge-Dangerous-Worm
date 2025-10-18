original_iv = b'4U+U\x0b\x04\x03\x14\x12\t3\x16"&\x12#'
xor_key = 102

real_iv = bytes([b ^ xor_key for b in original_iv])
print(real_iv.hex())