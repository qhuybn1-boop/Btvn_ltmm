# Mô phỏng mã hóa DES và AES-128

## Đề bài

1. Thiết kế và cài đặt hai thuật toán DES và AES-128. Dùng các ví dụ đã làm trên bảng trong những tuần học làm bộ dữ liệu kiểm thử (test vector).
2. In giá trị đầu ra tại từng trạng thái của mỗi thuật toán để có thể kiểm tra từng bước tính.
3. Tạo repository riêng cho môn học, tuân thủ yêu cầu của đề về việc không dùng nickname tài khoản Git. Đưa mã nguồn và kết quả chạy lên repository rồi nộp đường dẫn.

## Phân tích yêu cầu

**Đầu vào và phạm vi.** Chương trình mô phỏng chiều mã hóa một khối. Đầu vào gồm bản rõ và khóa, viết ở hệ thập lục phân. DES xử lý khối 64 bit với khóa biểu diễn bằng 64 bit, trong đó 56 bit tham gia sinh khóa vòng. AES-128 xử lý khối 128 bit với khóa 128 bit.

**Dữ liệu đối chiếu.** Đề gốc yêu cầu ví dụ trên bảng. Phiên bản này dùng hai ví dụ trong giáo trình có đủ bản rõ, khóa và bản mã kỳ vọng. Với DES, các Ví dụ 2.35, 2.36 và 2.40 cung cấp mốc kiểm tra cho cùng một cặp bản rõ và khóa. Với AES-128, Ví dụ 2.45 và Bảng 2.16 cho phép kiểm tra từng bước của vòng đầu. [Giáo trình DES, mục 2.2.4](https://mat-ma-ung-dung-ai.pages.dev/#/ch02/sec-2-2-4) · [Giáo trình AES, mục 2.2.5](https://mat-ma-ung-dung-ai.pages.dev/#/ch02/sec-2-2-5)

| Thuật toán | Bản rõ | Khóa | Bản mã kỳ vọng |
| --- | --- | --- | --- |
| DES | `0123456789ABCDEF` | `133457799BBCDFF1` | `85E813540F0AB405` |
| AES-128 | `00112233445566778899AABBCCDDEEFF` | `000102030405060708090A0B0C0D0E0F` | `69C4E0D86A7B0430D8CDB78070B4C55A` |

### DES — một khối 64 bit

Ví dụ dùng bản rõ `0123456789ABCDEF` và khóa `133457799BBCDFF1`. Các số trong bảng viết ở hệ hex. Hàm `hoan_vi` trong [DES.py](DES.py) đọc các bit theo thứ tự của bảng tương ứng.

| Bước | Quy tắc biến đổi | Giá trị trong ví dụ |
| --- | --- | --- |
| IP và chia khối | Sắp lại 64 bit theo bảng IP, rồi chia đôi thành L0 và R0. | `0123456789ABCDEF` → `CC00CCFFF0AAF0AA` → L0 = `CC00CCFF`, R0 = `F0AAF0AA` |
| PC-1 | Chọn và sắp lại 56 bit của khóa, bỏ 8 bit chẵn lẻ. Chia kết quả thành hai nửa 28 bit. | `133457799BBCDFF1` → C0 = `F0CCAAF`, D0 = `556678F` |
| Dịch vòng khóa | Dịch vòng trái từng nửa theo lịch của DES. Ở vòng 1, mỗi nửa dịch 1 bit. | C0: `F0CCAAF` → `E19955F`; D0: `556678F` → `AACCF1E` |
| PC-2 | Ghép hai nửa vừa dịch, chọn 48 bit theo bảng PC-2 để tạo khóa vòng. | `E19955FAACCF1E` → K1 = `1B02EFFC7072` |
| Mở rộng E | Mở rộng nửa phải từ 32 lên 48 bit bằng cách lặp lại một số bit theo bảng E. | R0 = `F0AAF0AA` → `7A15557A1555` |
| XOR khóa vòng | XOR kết quả mở rộng với K1 theo từng bit. | `7A15557A1555` XOR `1B02EFFC7072` → `6117BA866527` |
| Thay thế S-box | Chia thành tám nhóm 6 bit. Trong mỗi nhóm, hai bit ngoài chọn hàng, bốn bit giữa chọn cột. Ghép tám kết quả 4 bit. | `6117BA866527` → `5C82B597` |
| Hoán vị P | Sắp lại 32 bit đầu ra của các S-box theo bảng P. Đây là kết quả hàm vòng. | `5C82B597` → `234AA9BB` |
| Cập nhật L, R | L mới nhận R cũ. R mới bằng L cũ XOR kết quả hàm vòng. | L1 = `F0AAF0AA`. R1 = `CC00CCFF` XOR `234AA9BB` = `EF4A6544` |
| Ghép sau vòng 16 | Đặt R16 trước L16 để tạo khối 64 bit đầu vào cho hoán vị cuối. | R16 = `0A4CD995`, L16 = `43423234` → `0A4CD99543423234` |
| IP⁻¹ | Áp dụng hoán vị nghịch đảo của IP để thu bản mã. | `0A4CD99543423234` → `85E813540F0AB405` |

### AES-128 — một khối 128 bit

Ví dụ dùng bản rõ `00112233445566778899AABBCCDDEEFF` và khóa K0 = `000102030405060708090A0B0C0D0E0F`. Trong [aes128.py](aes128.py), cứ bốn byte liên tiếp tạo thành một cột của trạng thái.

| Bước | Quy tắc biến đổi | Giá trị trong ví dụ |
| --- | --- | --- |
| Mở rộng khóa | Hàm `mo_rong_khoa` xoay từ 4 byte cuối của khóa trước, thay byte qua S-box và XOR hằng số vòng vào byte đầu. Sau đó XOR lần lượt với các từ của khóa trước để tạo khóa mới. | K0 = `000102030405060708090A0B0C0D0E0F` → K1 = `D6AA74FDD2AF72FADAA678F1D6AB76FE` |
| AddRoundKey | XOR từng byte của trạng thái với byte cùng vị trí của khóa vòng. Lần đầu dùng K0. | Bản rõ `00112233445566778899AABBCCDDEEFF` → `00102030405060708090A0B0C0D0E0F0` |
| SubBytes | Thay mỗi byte bằng giá trị tra trong S-box AES. Ví dụ byte đầu `00` thành `63`. | `00102030405060708090A0B0C0D0E0F0` → `63CAB7040953D051CD60E0E7BA70E18C` |
| ShiftRows | Dịch vòng trái các hàng 0, 1, 2, 3 lần lượt 0, 1, 2, 3 byte. | `63CAB7040953D051CD60E0E7BA70E18C` → `6353E08C0960E104CD70B751BACAD0E7` |
| MixColumns | Nhân từng cột với ma trận cố định trong trường GF(2⁸). Chẳng hạn, cột đầu `6353E08C` thành `5F726415`. | `6353E08C0960E104CD70B751BACAD0E7` → `5F72641557F5BC92F7BE3B291DB9F91A` |

Vòng 1 kết thúc bằng AddRoundKey với K1 và cho trạng thái `89D810E8855ACE682D1843D8CB128FE4`. Các vòng 2–9 lặp lại bốn phép theo thứ tự SubBytes → ShiftRows → MixColumns → AddRoundKey. Vòng 10 dùng SubBytes → ShiftRows → AddRoundKey và cho bản mã `69C4E0D86A7B0430D8CDB78070B4C55A`.

## Chạy và kiểm tra kết quả

Mở PowerShell tại thư mục dự án với Python 3.10 trở lên. Lệnh đầu chạy cả hai ví dụ. Lệnh thứ hai đối chiếu các trạng thái tham chiếu, bản mã và cấu trúc bản ghi bằng bộ kiểm thử tự động.

```powershell
python main.py demo
python -m unittest discover -s tests -v
```

Trong bản ghi, tiền tố `01.` chỉ vòng 1. Với DES, có thể kiểm tra ngay `01.P = 234AA9BB`, sau đó kiểm tra nửa phải mới `01.R = EF4A6544`. Với AES-128, dòng `01.AddRoundKey = 89D810E8855ACE682D1843D8CB128FE4` là trạng thái cuối vòng 1, ghi theo thứ tự cột. Dòng `ciphertext` cuối mỗi ví dụ dùng để đối chiếu với bảng trên.

Để chạy từng thuật toán với bản rõ và khóa tự nhập, dùng lệnh `encrypt`. Mỗi tham số dữ liệu cần đủ 16 chữ số hex cho DES hoặc 32 chữ số hex cho AES-128.

```powershell
python main.py encrypt des 0123456789ABCDEF 133457799BBCDFF1
python main.py encrypt aes128 00112233445566778899AABBCCDDEEFF 000102030405060708090A0B0C0D0E0F
```

Bài nộp có [bản ghi đầy đủ của hai thuật toán](results/mo-phong.txt) và [kết quả chạy bộ kiểm thử](results/tests.txt). Để tạo lại bản ghi mô phỏng, chạy:

```powershell
python main.py demo --output results/mo-phong.txt
```
