<div align="center" dir="rtl">

# shircrypt (شیرکریپت)

**اکستنشن رمزنگاری مدرن، امن و مبتنی بر `Rust` و `abi3` برای MTProto 2.0 تلگرام — طراحی‌شده برای [Shirdal](https://github.com/Vicious-Cycle/shirdal)**

[English](README.md) | **فارسی**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Rust](https://img.shields.io/badge/rust-1.78+-000000.svg?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![PyPI](https://img.shields.io/pypi/v/shircrypt.svg?color=007ec6)](https://pypi.org/project/shircrypt/)
[![CI](https://github.com/Vicious-Cycle/shircrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/Vicious-Cycle/shirdal/actions/workflows/ci.yml)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)](LICENSE)

</div>

---

<div dir="rtl">

**shircrypt** جایگزین مدرن و بی‌دردسر برای اکستنشن‌های قدیمی C (مثل `TgCrypto`) است و در بنچمارک‌ها به‌طور میانگین **۴.۶۷ برابر** (و تا **۱۱.۸۴ برابر** در AES-CTR) سریع‌تر عمل می‌کند. هستهٔ آن با **Rust + PyO3 (`abi3-py311`)** نوشته شده؛ یعنی یک‌بار کامپایل می‌شود و روی پایتون ۳.۱۱ تا ۳.۱۵+ بدون نیاز به بیلد مجدد کار می‌کند، هیچ وابستگی به OpenSSL یا کتابخانه‌های C سیستم ندارد، از شتاب‌دهنده‌های سخت‌افزاری **AES-NI** و **ARMv8 Crypto** (گوشی و ترموکس) استفاده می‌کند و کلیدها را بلافاصله با `zeroize` از رم پاک می‌کند.

## معماری

```text
  کد پایتون شما (bytes / bytearray / memoryview)
                       │
          shircrypt.__init__ (انتخاب خودکار)
          ┌────────────┴────────────┐
          ▼                         ▼
   _shircrypt (Rust)        _fallback (پایتون)
  (PyO3 abi3-py311,       (پشتیبان با cryptography
   AES-NI / ARMv8 CE,      در صورت نبودن باینری)
   zeroize, GIL-free)
```

## مقایسه با `TgCrypto`

| ویژگی | `shircrypt` | `TgCrypto` | پایتون خالص |
| :--- | :--- | :--- | :--- |
| **سازگاری با نسخه‌های پایتون** | `abi3-py311` (یک فایل برای ۳.۱۱ تا ۳.۱۵+) | نیاز به بیلد مجدد در هر نسخه پایتون | مستقل از نسخه |
| **وابستگی سیستمی** | صفر (کاملاً Rust) | کامپایلر C + هدرهای پایتون | OpenSSL / ندارد |
| **امنیت حافظه و پاک‌سازی کلید** | حافظهٔ امن Rust + `zeroize` | اشاره‌گرهای دستی C | مدیریت‌شده |
| **شتاب سخت‌افزاری** | AES-NI (دسکتاپ) و ARMv8 Crypto (ترموکس) | AES-NI / حلقه C | کند |
| **آزادسازی GIL** | برای داده‌های `>= 4096` بایت آزاد می‌شود | آزاد می‌شود | GIL را قفل می‌کند |
| **توابع KDF پروتکل MTProto 2.0** | داخلی (`compute_msg_key` و `mtproto2_kdf`) | ندارد | پایتون `hashlib` |
| **پشتیبان خودکار (Fallback)** | سوئیچ خودکار به `cryptography` | خطا در صورت نبود کامپایلر | — |

## بنچمارک‌ها (مقایسه با TgCrypto)

**shircrypt** در مجموع ۳۰ سناریوی تست به‌طور میانگین **۴.۶۷ برابر سریع‌تر** از `TgCrypto` است (**۵.۱۱ برابر** در بافرهای ۶۴ کیلوبایت به بالا و **۳.۹۳ برابر** در بافرهای ۱ کیلوبایت و کمتر).

![shircrypt vs TgCrypto](benches/results/chart.svg)

| عملیات (بافر ۶۴ KiB) | `shircrypt` (Rust) | `TgCrypto` (C) | افزایش سرعت |
| :--- | ---: | ---: | ---: |
| **CTR-256** | **۸۲۷ MB/s** | ۷۰ MB/s | **۱۱.۸۴x** |
| **CBC-256 رمزگشایی** | **۶۰۳ MB/s** | ۸۲ MB/s | **۷.۳۶x** |
| **CBC-256 رمزنگاری** | **۳۲۲ MB/s** | ۸۰ MB/s | **۴.۰۲x** |
| **IGE-256 رمزنگاری** | **۳۱۴ MB/s** | ۸۱ MB/s | **۳.۸۹x** |
| **IGE-256 رمزگشایی** | **۱۹۶ MB/s** | ۷۸ MB/s | **۲.۴۹x** |
| **ارسال کامل پیام ۱ KiB MTProto 2.0** (KDF + IGE) | **۲۲.۰۸ µs** | ۳۱.۵۶ µs\* | **۱.۴۴x** |

<sub>\* `TgCrypto` تابع KDF داخلی ندارد؛ بنابراین در مقایسهٔ سرتاسری با `hashlib` پایتون ترکیب شده است. تست‌ها با پین روی یک هسته (Xeon E5-2620 v4، پایتون ۳.۱۱.۱۸، لینوکس x86_64، ۷ دور متناوب) انجام شده‌اند. همچنین `shircrypt` برای بافرهای `>= 4096` بایت GIL را آزاد می‌کند تا تردهای هم‌زمان برنامه قفل نشوند. مشاهدهٔ [گزارش کامل بنچمارک و روش‌شناسی](benches/results/results.md).</sub>

## نصب

```bash
pip install shircrypt
```

برای فعال‌سازی لایهٔ پشتیبان پایتونی در پلتفرم‌های خاص:

```bash
pip install "shircrypt[fallback]"
```

### نصب در ترموکس (Termux / Android)

در ترموکس به دو روش می‌توانید `shircrypt` را نصب و اجرا کنید:

۱. **نصب فوری بدون کامپایل (با لایهٔ Fallback):**
```bash
pkg install -y python-cryptography
pip install --no-build-isolation --no-deps -e .
```

۲. **نصب با هستهٔ بومی Rust (حداکثر سرعت + شتاب‌دهنده ARMv8 گوشی):**
```bash
pkg install -y rust binutils maturin
maturin develop --release
```

## شروع سریع

```python
import os
import shircrypt

print("بکند فعال:", shircrypt.BACKEND)  # "rust" یا "cryptography"

key = os.urandom(32)
iv_ige = os.urandom(32)
plaintext = b"0123456789abcdef" * 4

# رمزنگاری و رمزگشایی AES-256-IGE (بسته‌های MTProto 2.0)
ciphertext = shircrypt.ige256_encrypt(plaintext, key, iv_ige)
decrypted = shircrypt.ige256_decrypt(ciphertext, key, iv_ige)
assert decrypted == plaintext

# رمزنگاری جریانی AES-256-CTR با پشتیبانی از offset برای انتقال فایل
iv_ctr = os.urandom(16)
stream_chunk = shircrypt.ctr256_crypt(b"chunk-data", key, iv_ctr, offset=1024)

# استخراج کلید MTProto 2.0
auth_key = os.urandom(256)
msg_key = shircrypt.compute_msg_key(auth_key, plaintext, from_client=True)
aes_key, aes_iv = shircrypt.mtproto2_kdf(auth_key, msg_key, from_client=True)
```

## مستندات

- [مستندات کامل و مرجع API فارسی](docs/fa/README.md)
- [معماری و بهینه‌سازی‌ها (انگلیسی)](docs/architecture.md)
- [مرجع کامل API (انگلیسی)](docs/api.md)

## تست و بنچمارک

```bash
python3 -m unittest discover -s tests -v
python3 benches/bench_shircrypt.py
pip install shircrypt TgCrypto && python3 benches/compare_tgcrypto.py
```

## امنیت، مشارکت و مجوز

- گزارش باگ امنیتی: [SECURITY.md](SECURITY.md)
- راهنمای مشارکت: [CONTRIBUTING.md](CONTRIBUTING.md)
- تاریخچه تغییرات: [CHANGELOG.md](CHANGELOG.md)
- مجوز: [LGPL-3.0-or-later](LICENSE)

</div>
