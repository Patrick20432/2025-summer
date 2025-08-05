# utils.py
def bytes_to_words(b):
    """将16字节转换为4个32位整数"""
    return [
        (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3],
        (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7],
        (b[8] << 24) | (b[9] << 16) | (b[10] << 8) | b[11],
        (b[12] << 24) | (b[13] << 16) | (b[14] << 8) | b[15],
    ]

def words_to_bytes(words):
    """将4个32位整数转换为16字节"""
    return bytes([
        (words[0] >> 24) & 0xFF, (words[0] >> 16) & 0xFF, (words[0] >> 8) & 0xFF, words[0] & 0xFF,
        (words[1] >> 24) & 0xFF, (words[1] >> 16) & 0xFF, (words[1] >> 8) & 0xFF, words[1] & 0xFF,
        (words[2] >> 24) & 0xFF, (words[2] >> 16) & 0xFF, (words[2] >> 8) & 0xFF, words[2] & 0xFF,
        (words[3] >> 24) & 0xFF, (words[3] >> 16) & 0xFF, (words[3] >> 8) & 0xFF, words[3] & 0xFF
    ])
