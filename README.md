# LoaderFilter — TemporalKG Subproject / Tool

> **Status:** Repository-verified canonical structure
> **Standard:** TemporalKG Repository Contract (Project Structure & Naming Rules v2.0)
> **Pipeline Model:** Step-oriented (`Code/` + `utils/` + `tools/` + `tests/`)

Bộ lọc **thận trọng** cho báo cáo sandbox CAPE JSON: tìm candidate loader từ metadata nhãn, chỉ kết luận "loader đã chạy" (`loader_run_observed`) khi có evidence thực thi và binding đáng tin cậy, tách biệt hoàn toàn với "sample có nhãn loader". Công cụ chỉ đọc báo cáo JSON, không chạy mẫu, không sửa dữ liệu nguồn.

---

## 1. Purpose (Mục đích)

- **Lọc và phân loại mã độc Loader**: Bóc tách chính xác các hành vi của loader (smokeloader, guloader, sload, v.v.) từ tập báo cáo sandbox CAPE JSON.
- **Tách biệt 3 tầng đánh giá**: Candidate (tín hiệu nhãn/metadata) $\rightarrow$ Observed (bằng chứng thực thi kỹ thuật có binding tin cậy) $\rightarrow$ Payload Execution (thực thi thứ cấp).
- **Chuẩn hóa dữ liệu đầu vào cho TemporalKG**: Cung cấp tập dữ liệu đã xác thực và phân loại cho các pipeline hạ tầng downstream (như `TransitionBuilder` và `Forecasting`).

---

## 2. Actual Directory Tree (Cây thư mục thực tế)

```text
loaderfilter_tool/
├── Code/                                # Pipeline business logic theo step
│   ├── __init__.py
│   ├── step1_discover_sources.py        # Quét và định danh file báo cáo
│   ├── step2_build_inventory.py         # Khớp nhãn (AVClass/CAPE/consensus) & phân loại
│   ├── step3_scan_evidence.py           # Stream parse CAPE report & bóc tách fact/process
│   ├── step4_decide_and_manifest.py     # Đánh giá policy (conservative-v1) & xuất manifest
│   └── step5_run_qa.py                  # Chạy bộ kiểm thử chất lượng (QC-01..15)
│
├── utils/                               # Shared domain helpers (tuân thủ Rule 8.2)
│   ├── __init__.py
│   ├── configs.py                       # Cấu hình, schema, path resolution (BASE_DIR)
│   ├── logging_utils.py                 # RunLogger chuẩn Canonical TemporalKG
│   ├── io_utils.py                      # I/O an toàn, atomic write, hash SHA256, long-path
│   ├── identity_utils.py                # Resolve SHA256 và source identity
│   ├── taxonomy_utils.py                # Taxonomy loader & model
│   ├── label_utils.py                   # LabelStore & mapping parser
│   ├── inventory_utils.py               # Inventory entry classification
│   ├── cape_adapter.py                  # Streaming parser cho CAPE JSON
│   ├── evidence_utils.py                # Fact, process, artifact evidence collector
│   ├── policy_utils.py                  # Conservative-v1 decision logic
│   ├── review_utils.py                  # Template review, human audit & effective bindings
│   ├── manifest_utils.py                # CSV generation (anti-formula injection)
│   ├── qa_utils.py                      # QC-01..15 QA verification checks
│   ├── state_utils.py                   # SQLite StateStore cho checkpoint / resume
│   ├── scheduler_utils.py               # Multi-worker process scheduling
│   ├── models.py                        # Dataclasses & enumerations
│   ├── errors.py                        # Exception types & exit codes
│   └── locking_utils.py                 # RunLock file lock
│
├── tools/                               # CLI & công cụ phụ trợ (Rule 17)
│   ├── cli.py                           # CLI entrypoint chính (`loaderfilter`)
│   ├── export_run.py                    # Xuất dataset theo selection / format
│   ├── verify_run.py                    # Kiểm tra toàn vẹn run, checksums, QA
│   └── organize_by_year.py              # Gom nhóm báo cáo JSON theo năm
│
├── configs/                             # Cấu hình JSON & seed taxonomy (Rule 11)
│   ├── config.example.json
│   ├── config.volume3.json
│   ├── config.volume4.json
│   └── taxonomy.seed.json
│
├── tests/                               # Kiểm thử tự động (Rule 19)
│   ├── unit/
│   │   ├── test_cape_adapter.py
│   │   ├── test_manifests.py
│   │   └── test_regression_review.py
│   ├── integration/
│   │   └── test_end_to_end.py
│   └── fixtures/
│       └── cape_small.json
│
├── State/                               # Mutable checkpoint / audit state (Rule 16.1)
│   └── Logs/                            # Stable JSON logs upserted by run_id (Rule 15)
│
├── Results/                             # Published / run output results
├── loaderfilter/                        # Backward-compatibility shims cho consumer cũ
├── run_pipeline.py                      # Pipeline orchestrator
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## 3. Pipeline Order (Trình tự thực thi)

Pipeline vận hành theo 5 bước tuần tự:

1. **Step 1 — Discovery (`step1_discover_sources.py`)**: Quét `inputs` theo cấu hình `include`/`exclude`, loại bỏ symlink/junction/reparse points, deduplicate physical files `(st_dev, st_ino)`, prefetch target SHA256.
2. **Step 2 — Inventory (`step2_build_inventory.py`)**: Đọc ba bảng mapping (AVClass, CAPE, consensus) và taxonomy họ loader; phân loại `seed_candidate`, `candidate`, `mismatch`, `not_candidate`.
3. **Step 3 — Evidence Scanning (`step3_scan_evidence.py`)**: Multi-worker stream-parse báo cáo CAPE JSON bằng `ijson`, bóc tách process tree, API calls, dropped files, payloads thành các `Fact` có `evidence_id`.
4. **Step 4 — Decision & Manifest (`step4_decide_and_manifest.py`)**: Đánh giá theo chính sách `conservative-v1`, kết hợp human reviews; xuất các bảng manifest CSV (UTF-8 BOM, an toàn trước formula injection) và `all_reports.jsonl`.
5. **Step 5 — QA Verification (`step5_run_qa.py`)**: Thực thi 15 tiêu chuẩn kiểm định chất lượng (QC-01 đến QC-15), xác minh tính toàn vẹn dữ liệu và đối soát trạng thái.

---

## 4. Input/Output Contracts (Hợp đồng dữ liệu)

### Input Contract
- **Báo cáo Sandbox**: Định dạng CAPE JSON (hoặc Cuckoo).
- **Taxonomy**: `configs/taxonomy.seed.json` định nghĩa danh sách các họ loader hạt giống và alias hợp lệ.
- **Label Mappings**: File JSON ánh xạ `report` $\rightarrow$ `sha256` $\rightarrow$ `family` (AVClass, CAPE, Consensus).

### Output Contract
Mỗi run được lưu tại `Results/<run_id>/` (hoặc thư mục chỉ định trong config):
- `run.json`: Metadata tổng quan của run.
- `state.sqlite`: SQLite database lưu trữ trạng thái chi tiết, phục vụ resume/audit.
- `config/`: Snapshot bất biến của config, taxonomy, fingerprints.
- `manifest/`:
  - `all_sources.csv`: Tất cả các source phát hiện được.
  - `seed_candidates.csv`: Các mẫu thuộc họ loader hạt giống.
  - `candidates.csv`: Tập candidate loader mở rộng.
  - `observed.csv`: Mẫu chứng minh được hành vi loader đã thực thi (`loader_run_observed`).
  - `payload_execution.csv`: Bằng chứng thực thi payload thứ cấp.
  - `review_queue.csv`: Danh sách cần chuyên gia phân tích/đối soát.
  - `all_reports.jsonl`: Dòng dữ liệu JSONL tổng hợp.
- `evidence/by_report/<report_id>/`:
  - `report.json`, `facts.jsonl`, `processes.jsonl`.
- `qa/`: `summary.json`, `checks.jsonl`, `run_summary.json`.

---

## 5. State & Log Path (Trạng thái và Nhật ký)

- **Audit Logs chuẩn TemporalKG**: Được lưu tại `State/Logs/<module>_logs.json`.
  - Mỗi lần chạy ghi đúng 1 bản ghi JSON trong mảng JSON ổn định (upsert theo `run_id`).
  - Schema bản ghi: `run_id`, `module`, `status`, `started_at`, `finished_at`, `duration_seconds`, `params`, `events`, `summary`, `error`.
- **Run State Database**: `state.sqlite` nằm bên trong thư mục của từng run để phục vụ checkpoint và resume độc lập.

---

## 6. Dependency & Installation (Cài đặt)

Yêu cầu Python $\ge$ 3.11 (đã kiểm tra tương thích trên Python 3.13 và 3.14 trên Windows).

```powershell
# Cài đặt môi trường từ thư mục gốc
python -m pip install -r requirements.txt
python -m pip install -e .

# Kiểm tra CLI
loaderfilter --version
```

---

## 7. Run Commands (Lệnh chạy)

### Chạy qua Pipeline Orchestrator (`run_pipeline.py`)
```powershell
# Chạy toàn bộ pipeline với config volume 4
python run_pipeline.py --config configs/config.volume4.json

# Giới hạn số lượng mẫu và tăng số worker
python run_pipeline.py --config configs/config.volume4.json --workers 4 --limit 100

# Resume một run trước đó
python run_pipeline.py --resume Results/<run_id> --config configs/config.volume4.json
```

### Chạy từng Step riêng biệt trong `Code/`
```powershell
# Step 1: Quét nguồn dữ liệu
python Code/step1_discover_sources.py --config configs/config.volume4.json

# Step 2: Xây dựng inventory
python Code/step2_build_inventory.py --config configs/config.volume4.json
```

### Chạy qua CLI (`loaderfilter`)
```powershell
# Validate cấu hình và taxonomy
loaderfilter validate --config configs/config.volume4.json

# Quét sandbox dataset (mode evidence, scope all)
loaderfilter scan --config configs/config.volume4.json --mode evidence --scope all --workers 4

# Export báo cáo seed loader ra thư mục riêng chia theo năm
loaderfilter export --run Results/<run_id> --selection seed-candidates --format reports --dest Results/exports/seed --group-by-year

# Xác minh toàn vẹn run và export
loaderfilter verify --run Results/<run_id> --exports Results/exports/seed

# Chia thư mục JSON báo cáo theo năm thực thi
loaderfilter organize-by-year --dir <path_to_json_dir> --mode move
```

Mã thoát (Exit Codes):
- `0`: Thành công.
- `2`: Lỗi cú pháp CLI, cấu hình, taxonomy, hoặc xung đột run lock.
- `3`: Hoàn thành một phần (báo cáo lỗi, giới hạn tài nguyên).
- `4`: Lỗi toàn vẹn dữ liệu, kiểm thử QA thất bại.
- `130`: Bị ngắt bởi người dùng (Ctrl+C).

---

## 8. Environment Variables (Biến môi trường)

- `LOADERFILTER_CONFIG`: Đường dẫn mặc định đến file cấu hình nếu không truyền `--config`.
- `LOADERFILTER_LOG_LEVEL`: Mức độ chi tiết log (`INFO`, `DEBUG`, `WARNING`, `ERROR`).
- `LOADERFILTER_WORKERS`: Số tiến trình worker mặc định cho scheduler.

---

## 9. Generated & Gitignored Artifacts (Các tệp tự sinh)

Các tệp sau được sinh tự động khi chạy và không được commit vào Git:
- `Results/*`: Kết quả quét, export và manifest của các run.
- `State/Logs/*`: File audit log runtime.
- `*.tmp`, `*.lock`, `*.sqlite`: File khóa và database tạm.
- `dist/`, `build/`, `*.egg-info`: Thư mục build package.
- `__pycache__/`, `.pytest_cache/`: Cache thực thi Python và test.

---

## 10. Tests (Kiểm thử)

Bộ kiểm thử tự động gồm 38 bài test bao phủ toàn bộ pipeline, bộ chuyển đổi CAPE stream, cơ chế binding, export, QA và toàn vẹn checksum:

```powershell
# Chạy toàn bộ test suite
python -m pytest

# Chạy riêng unit tests
python -m pytest tests/unit/

# Chạy riêng integration tests
python -m pytest tests/integration/
```

---

## 11. Known Legacy Exceptions (Quy ước kế thừa)

- Thư mục `loaderfilter/` ở thư mục gốc được duy trì dưới dạng shim layer để đảm bảo tính tương thích ngược hoàn toàn cho các script hoặc consumer cũ sử dụng cú pháp `from loaderfilter... import ...`. Toàn bộ mã nguồn sản xuất chính thức tuân thủ cấu trúc `Code/` và `utils/`.
- File cấu hình sử dụng đường dẫn tương đối được resolve dựa trên `BASE_DIR = Path(__file__).resolve().parent.parent`.
