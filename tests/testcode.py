import subprocess
import sys
import unittest
from pathlib import Path

import DES
import aes128
from main import EXAMPLES

DES_EXPECTED = {
    "IP": "CC00CCFFF0AAF0AA",
    "L0": "CC00CCFF",
    "R0": "F0AAF0AA",
    "PC-1": "F0CCAAF556678F",
    "C0": "F0CCAAF",
    "D0": "556678F",
    "01.C": "E19955F",
    "01.D": "AACCF1E",
    "01.K": "1B02EFFC7072",
    "02.K": "79AED9DBC9E5",
    "16.K": "CB3D8B0E17F5",
    "01.E": "7A15557A1555",
    "01.XOR": "6117BA866527",
    "01.S-box": "5C82B597",
    "01.P": "234AA9BB",
    "01.L": "F0AAF0AA",
    "01.R": "EF4A6544",
    "R16||L16": "0A4CD99543423234",
    "ciphertext": "85E813540F0AB405",
}
AES_BOOK_EXPECTED = {
    "00.AddRoundKey": "00102030405060708090A0B0C0D0E0F0",
    "01.SubBytes": "63CAB7040953D051CD60E0E7BA70E18C",
    "01.ShiftRows": "6353E08C0960E104CD70B751BACAD0E7",
    "01.MixColumns": "5F72641557F5BC92F7BE3B291DB9F91A",
    "01.K": "D6AA74FDD2AF72FADAA678F1D6AB76FE",
    "01.AddRoundKey": "89D810E8855ACE682D1843D8CB128FE4",
    "ciphertext": "69C4E0D86A7B0430D8CDB78070B4C55A",
}


class CipherTests(unittest.TestCase):
    def doi_chieu_vi_du(self, name, encrypt, expected):
        _, plaintext, key = EXAMPLES[name]
        ciphertext, trace = encrypt(bytes.fromhex(plaintext), bytes.fromhex(key))
        self.assertEqual(ciphertext.hex().upper(), expected["ciphertext"])
        for label, value in expected.items():
            with self.subTest(state=label):
                self.assertEqual(trace[label], value)
        return trace

    def test_cac_trang_thai_des_trong_sach(self):
        trace = self.doi_chieu_vi_du("des-book", DES.ma_hoa_khoi, DES_EXPECTED)
        widths = {"C": 7, "D": 7, "K": 12, "E": 12, "XOR": 12,
                  "S-box": 8, "P": 8, "L": 8, "R": 8}
        keys = [f"{number:02d}.{step}" for number in range(1, 17) for step in widths]
        self.assertEqual(list(trace)[8:-2], keys)
        for label in keys:
            self.assertEqual(len(trace[label]), widths[label.split(".")[1]])

    def test_cac_trang_thai_aes_trong_sach(self):
        trace = self.doi_chieu_vi_du("aes-book", aes128.ma_hoa_khoi, AES_BOOK_EXPECTED)
        keys = ["00.K", "00.AddRoundKey"]
        for number in range(1, 10):
            for label in ("K", "SubBytes", "ShiftRows", "MixColumns", "AddRoundKey"):
                keys.append(f"{number:02d}.{label}")
        keys.extend(("10.K", "10.SubBytes", "10.ShiftRows", "10.AddRoundKey"))
        self.assertEqual(list(trace)[2:-1], keys)
        for label in keys:
            self.assertEqual(len(trace[label]), 32)

    def test_phep_tinh_truong_huu_han_aes(self):
        self.assertEqual(aes128.nhan_trong_truong_huu_han(0x26, 0x9E), 0x2F)
        self.assertEqual(aes128.nhan_trong_truong_huu_han(0x57, 0x83), 0xC1)
        self.assertEqual(aes128.tinh_gia_tri_hop_s(0x53), 0xED)

    def chay_dong_lenh(self, *args):
        project = Path(__file__).resolve().parents[1]
        return subprocess.run(
            [sys.executable, str(project / "main.py"), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_mo_phong_hai_vi_du_giao_trinh(self):
        result = self.chay_dong_lenh("demo")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        ban_ma = [line.split("=")[1].strip() for line in result.stdout.splitlines()
                  if line.startswith("ciphertext")]
        self.assertEqual(ban_ma, [DES_EXPECTED["ciphertext"], AES_BOOK_EXPECTED["ciphertext"]])

    def test_ma_hoa_du_lieu_nhap_tu_dong_lenh(self):
        result = self.chay_dong_lenh("encrypt", "des", "0x0123456789abcdef", "133457799BBCDFF1")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn(DES_EXPECTED["ciphertext"], result.stdout)

    def test_bao_loi_do_dai_va_ky_tu_sai(self):
        key = "133457799BBCDFF1"
        cases = (
            ("00", key, "Plaintext must contain 16 hex digits"),
            ("0123456789ABCDEF", "FF", "Key must contain 16 hex digits"),
            ("Z123456789ABCDEF", key, "non-hex character"),
        )
        for plaintext, key_input, error in cases:
            with self.subTest(plaintext=plaintext, key=key_input):
                result = self.chay_dong_lenh("encrypt", "des", plaintext, key_input)
                self.assertEqual(result.returncode, 2)
                self.assertIn(error, result.stderr)


if __name__ == "__main__":
    unittest.main()
