"""Chạy các ví dụ hoặc nhập một khối hex để xem các bước mã hóa."""

import argparse
from pathlib import Path

import DES
import aes128

ALGORITHMS = {
    "des": (8, DES.ma_hoa_khoi),
    "aes128": (16, aes128.ma_hoa_khoi),
}
EXAMPLES = {
    "des-book": ("des", "0123456789ABCDEF", "133457799BBCDFF1"),
    "aes-book": (
        "aes128",
        "00112233445566778899AABBCCDDEEFF",
        "000102030405060708090A0B0C0D0E0F",
    ),
}


def doc_chuoi_thap_luc_phan(text: str, byte_count: int, label: str) -> bytes:
    if text[:2].lower() == "0x":
        text = text[2:]
    if len(text) != byte_count * 2:
        raise ValueError(f"{label} must contain {byte_count * 2} hex digits.")
    if any(digit not in "0123456789abcdefABCDEF" for digit in text):
        raise ValueError(f"{label} contains a non-hex character.")
    return bytes.fromhex(text)


def dinh_dang_ket_qua_ma_hoa(algorithm: str, plaintext: str, key: str) -> str:
    byte_count, encrypt = ALGORITHMS[algorithm]
    block = doc_chuoi_thap_luc_phan(plaintext, byte_count, "Plaintext")
    key_bytes = doc_chuoi_thap_luc_phan(key, byte_count, "Key")
    _, trace = encrypt(block, key_bytes)
    name = "DES" if algorithm == "des" else "AES-128"
    entries = [f"{label:<17} = {value}" for label, value in trace.items()]
    return "\n".join([name, *entries])


def tao_bo_phan_tich_tham_so() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Single-block DES and AES-128 simulator")
    commands = parser.add_subparsers(dest="command", required=True)

    demo = commands.add_parser("demo", help="Run both textbook examples")
    demo.add_argument("--output", type=Path, help="Also save the trace as a UTF-8 file")

    encrypt = commands.add_parser("encrypt", help="Encrypt one hex block")
    encrypt.add_argument("algorithm", choices=ALGORITHMS)
    encrypt.add_argument("plaintext")
    encrypt.add_argument("key")
    encrypt.add_argument("--output", type=Path, help="Also save the trace as a UTF-8 file")
    return parser


def chay_chuong_trinh() -> None:
    parser = tao_bo_phan_tich_tham_so()
    args = parser.parse_args()
    try:
        if args.command == "encrypt":
            output = dinh_dang_ket_qua_ma_hoa(args.algorithm, args.plaintext, args.key)
        else:
            output = "\n\n".join(dinh_dang_ket_qua_ma_hoa(*case) for case in EXAMPLES.values())
        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8", newline="\n")
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(output)


if __name__ == "__main__":
    chay_chuong_trinh()
