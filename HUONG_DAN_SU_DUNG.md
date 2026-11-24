# HƯỚNG DẪN CÀI ĐẶT VÀ SỬ DỤNG LOADERFILTER TOOL

`LoaderFilter` là công cụ chuyên dụng dùng để quét, phân loại, bóc tách bằng chứng hành vi và trích xuất các báo cáo sandbox JSON của mã độc **Malware Loader** (CAPE / Cuckoo sandbox format).
Công cụ đã được chuẩn hóa theo cấu trúc repository step-oriented của TemporalKG.

---

## 1. Yêu cầu hệ thống
- **Hệ điều hành:** Windows 10/11 hoặc Linux / macOS
- **Python:** Phiên bản $\ge$ 3.11 (đã kiểm tra và tương thích tốt trên Python 3.11, 3.12, 3.13, 3.14)

---

## 2. Cách cài đặt

Người nhận có thể chọn 1 trong 2 cách sau:

### Cách A: Cài đặt nhanh bằng file Wheel (.whl)
Trong thư mục `dist/` có sẵn file `loaderfilter-0.1.0-py3-none-any.whl`.
Mở PowerShell / Terminal tại thư mục giải nén và chạy:
```powershell
pip install dist/loaderfilter-0.1.0-py3-none-any.whl
```

### Cách B: Cài đặt từ mã nguồn trực tiếp
Mở PowerShell / Terminal tại thư mục gốc của tool và chạy:
```powershell
pip install -r requirements.txt
pip install -e .
```
*(Nếu muốn cài thêm thư viện chạy test unit, dùng: `pip install -e ".[dev]"`)*

Sau khi cài đặt xong, kiểm tra bằng lệnh:
```powershell
loaderfilter --version
```

---

## 3. Các tính năng & Lệnh thông dụng

### 3.1. Phân loại và chia file JSON báo cáo theo năm (Organize by year)
Dùng để đọc tất cả các file JSON báo cáo sandbox và tự động gom nhóm vào các thư mục con theo năm thực thi thực tế (`2024`, `2023`,...):
```powershell
# Di chuyển file trực tiếp vào các folder năm trong thư mục:
loaderfilter organize-by-year --dir <đường_dẫn_thư_mục_json> --mode move

# Hoặc sao chép sang một thư mục mới:
loaderfilter organize-by-year --dir <thư_mục_nguồn> --out <thư_mục_đích> --mode copy
```

### 3.2. Quét tập dữ liệu Sandbox (Scan)
Phân tích toàn bộ tập báo cáo CAPE JSON để lọc ra các ứng viên Malware Loader:
```powershell
# Chạy qua CLI loaderfilter:
loaderfilter scan `
  --config configs/config.volume4.json `
  --mode evidence `
  --scope all `
  --workers 4

# Hoặc chạy qua Pipeline Orchestrator:
python run_pipeline.py --config configs/config.volume4.json --workers 4
```

### 3.3. Trích xuất file báo cáo Loader (Export)
Trích xuất các báo cáo đã lọc ra một thư mục riêng:
```powershell
# Xuất các mẫu Loader và tự động chia theo năm thực thi:
loaderfilter export `
  --run Results/<run_id> `
  --selection seed-candidates `
  --format reports `
  --dest Results/exports/seed_loaders `
  --group-by-year
```

Các lựa chọn `--selection`:
- `seed-candidates`: Các mẫu thuộc họ loader hạt giống đã biết (`smokeloader`, `guloader`, `sload`,...).
- `candidates`: Tất cả các mẫu có dấu hiệu loader (bao gồm cả nghi vấn).
- `observed`: Các mẫu chứng minh được hành vi loader đã thực thi trong sandbox (`loader_run_observed`).

### 3.4. Kiểm tra toàn vẹn dữ liệu (Verify)
Kiểm tra checksum SHA256 và QA toàn vẹn của kết quả scan/export:
```powershell
loaderfilter verify --run Results/<run_id> --exports Results/exports/seed_loaders
```

---

## 4. Chạy kiểm thử tự động (Unit & Integration Tests)
Để đảm bảo tất cả các tính năng hoạt động hoàn hảo trên máy mới:
```powershell
python -m pytest
```
*(Tất cả 38 bài test kiểm thử tự động tại `tests/unit/` và `tests/integration/` sẽ chạy và báo pass).*
