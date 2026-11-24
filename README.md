# Mô phỏng DES và AES-128

Bài tập mô phỏng mã hóa một khối. Chương trình in khóa con và trạng thái sau từng phép biến đổi để đối chiếu với hai ví dụ trong giáo trình.

## Chạy chương trình

Cần Python 3.10 trở lên. Mở PowerShell tại thư mục dự án.

```powershell
python main.py demo
python -m unittest discover -s tests -v
```

Để nhập một cặp bản rõ và khóa ở dạng hex, dùng lệnh `encrypt`. DES yêu cầu 16 chữ số hex cho mỗi giá trị. AES-128 yêu cầu 32 chữ số hex cho mỗi giá trị. Có thể thêm tiền tố `0x`.

```powershell
python main.py encrypt des 0123456789ABCDEF 133457799BBCDFF1
python main.py encrypt aes128 00112233445566778899AABBCCDDEEFF 000102030405060708090A0B0C0D0E0F
```

## Xem và tái tạo kết quả

| Ca | Bản ghi | Mốc đối chiếu |
| --- | --- | --- |
| DES và AES-128 trong giáo trình | [mo-phong.txt](results/mo-phong.txt) | DES `85E813540F0AB405`, AES-128 `69C4E0D86A7B0430D8CDB78070B4C55A` |
| Kiểm thử tự động | [tests.txt](results/tests.txt) | Trạng thái tham chiếu, số vòng, độ rộng hex và kiểm tra đầu vào |

```powershell
python main.py demo --output results/mo-phong.txt
```

Trong bản ghi, tiền tố `01.` chỉ vòng 1. Với DES, mỗi chữ số hex ở dòng `S-box` tương ứng với đầu ra 4 bit của một hộp thế, theo thứ tự S1 đến S8. Với AES-128, các dòng trạng thái ghi 16 byte theo thứ tự cột. Vòng 0 thực hiện AddRoundKey ban đầu, còn vòng 10 thực hiện SubBytes, ShiftRows và AddRoundKey.


Giáo trình [mục 2.2.4 — DES](https://mat-ma-ung-dung-ai.pages.dev/#/ch02/sec-2-2-4) và [mục 2.2.5 — AES](https://mat-ma-ung-dung-ai.pages.dev/#/ch02/sec-2-2-5).
