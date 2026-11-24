"""Mã hóa và ghi trạng thái DES theo mục 2.2.4."""

IP = (
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
)
INVERSE_IP = tuple(IP.index(bit) + 1 for bit in range(1, 65))
E = (
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
)
P = (
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
)
PC1 = (
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
)
PC2 = (
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
)
SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

# Mỗi chuỗi là một hàng gồm 16 giá trị hex, giữ cách sắp xếp của bảng DES.
S_BOXES = (
    ("E4D12FB83A6C5907", "0F74E2D1A6CB9538", "41E8D62BFC973A50", "FC8249175B3EA06D"),
    ("F18E6B34972DC05A", "3D47F28EC01A69B5", "0E7BA4D158C6932F", "D8A13F42B67C05E9"),
    ("A09E63F51DC7B428", "D709346A285ECBF1", "D6498F30B12C5AE7", "1AD069874FE3B52C"),
    ("7DE3069A1285BC4F", "D8B56F03472C1AE9", "A690CB7DF13E5284", "3F06A1D8945BC72E"),
    ("2C417AB6853FD0E9", "EB2C47D150FA3986", "421BAD78F9C5630E", "B8C71E2D6F09A453"),
    ("C1AF92680D34E75B", "AF427C9561DE0B38", "9EF528C3704A1DB6", "432C95FABE17608D"),
    ("4B2EF08D3C975A61", "D0B7491AE35C2F86", "14BDC37EAF680592", "6BD814A7950FE23C"),
    ("D2846FB1A93E50C7", "1FD8A374C56B0E92", "7B419CE206ADF358", "21E74A8DFC90356B"),
)


def chon_vi_tri(values, table):
    """Bảng đánh số từ 1 và đọc từ bit cao nhất."""
    return tuple(values[position - 1] for position in table)


def hoan_vi(value, width, table):
    bits = tuple((value >> offset) & 1 for offset in range(width - 1, -1, -1))
    result = 0
    for bit in chon_vi_tri(bits, table):
        result = (result << 1) | bit
    return result


def dich_vong_nua_khoa(half, shift):
    return ((half << shift) | (half >> (28 - shift))) & 0xFFFFFFF


def thay_the_qua_hop_s(value):
    result = 0
    for index, box in enumerate(S_BOXES):
        group = (value >> (42 - 6 * index)) & 0x3F
        row = ((group >> 4) & 2) | (group & 1)
        column = (group >> 1) & 0xF
        result = (result << 4) | int(box[row][column], 16)
    return result


def ma_hoa_khoi(plaintext: bytes, key: bytes) -> tuple[bytes, dict[str, str]]:
    """Trả về bản mã 8 byte và các giá trị hex theo thứ tự tính."""
    if len(plaintext) != 8 or len(key) != 8:
        raise ValueError("DES yêu cầu bản rõ và khóa dài 8 byte.")

    trace = {"plaintext": plaintext.hex().upper(), "key": key.hex().upper()}
    initial = hoan_vi(int.from_bytes(plaintext, "big"), 64, IP)
    left, right = initial >> 32, initial & 0xFFFFFFFF
    trace.update(IP=f"{initial:016X}", L0=f"{left:08X}", R0=f"{right:08X}")

    key_bits = hoan_vi(int.from_bytes(key, "big"), 64, PC1)
    c_half, d_half = key_bits >> 28, key_bits & 0xFFFFFFF
    trace.update({"PC-1": f"{key_bits:014X}", "C0": f"{c_half:07X}", "D0": f"{d_half:07X}"})
    for number, shift in enumerate(SHIFTS, start=1):
        c_half = dich_vong_nua_khoa(c_half, shift)
        d_half = dich_vong_nua_khoa(d_half, shift)
        round_key = hoan_vi((c_half << 28) | d_half, 56, PC2)
        expanded = hoan_vi(right, 32, E)
        mixed = expanded ^ round_key
        substituted = thay_the_qua_hop_s(mixed)
        permuted = hoan_vi(substituted, 32, P)
        left, right = right, left ^ permuted

        prefix = f"{number:02d}"
        trace.update({
            f"{prefix}.C": f"{c_half:07X}",
            f"{prefix}.D": f"{d_half:07X}",
            f"{prefix}.K": f"{round_key:012X}",
            f"{prefix}.E": f"{expanded:012X}",
            f"{prefix}.XOR": f"{mixed:012X}",
            f"{prefix}.S-box": f"{substituted:08X}",
            f"{prefix}.P": f"{permuted:08X}",
            f"{prefix}.L": f"{left:08X}",
            f"{prefix}.R": f"{right:08X}",
        })

    preoutput = (right << 32) | left
    ciphertext = hoan_vi(preoutput, 64, INVERSE_IP).to_bytes(8, "big")
    trace["R16||L16"] = f"{preoutput:016X}"
    trace["ciphertext"] = ciphertext.hex().upper()
    return ciphertext, trace
