<div dir="rtl">

# مستندات کامل `shircrypt`

این راهنما مرجع کامل معماری، بهینه‌سازی‌ها و توابع کتابخانهٔ `shircrypt` است.

## چرا `shircrypt`؟
1. **سازگاری دائمی با نسخه‌های پایتون (`abi3-py311`):** باینری کامپایل‌شده روی پایتون ۳.۱۱ تا ۳.۱۵+ بدون نیاز به بیلد مجدد کار می‌کند.
2. **صفر وابستگی C/OpenSSL:** مستقیماً با crate های خالص Rust نوشته شده و روی ترموکس، لینوکس، مک و ویندوز مشکل هدر یا لینک ندارد.
3. **تخصیص یک‌باره حافظه و Zero-Copy:** ورودی‌ها بدون کپی اضافه خوانده می‌شوند و خروجی مستقیماً در بافر پایتون ساخته می‌شود.
4. **آزادسازی هوشمند GIL:** برای بسته‌های کوچک کنترل بدون هزینهٔ سوئیچ اجرا می‌شود و برای داده‌های بزرگ (`>= 4096` بایت) GIL را آزاد می‌کند تا `asyncio` قفل نشود.
5. **پاک‌سازی امن کلیدها (`zeroize`):** کلیدها و متغیرهای میانی بلافاصله پس از اتمام عملیات از رم پاک می‌شوند.

---

## مرجع توابع (API)

تمام توابع ورودی‌های `bytes`، `bytearray` و `memoryview` را می‌پذیرند و در صورت نامعتبر بودن طول کلید، IV یا مضرب ۱۶ نبودن داده، خطای `ValueError` برمی‌گردانند.

### `shircrypt.BACKEND`
مشخص می‌کند کدام موتور فعال است: `"rust"` (اکستنشن بومی) یا `"cryptography"` (لایهٔ پشتیبان پایتونی).

### `ige256_encrypt(data, key, iv) -> bytes`
رمزنگاری AES-256-IGE برای بسته‌های MTProto 2.0.
- `data`: بایت‌هایی با طول مضرب ۱۶
- `key`: کلید ۳۲ بایتی
- `iv`: بردار اولیه ۳۲ بایتی

### `ige256_decrypt(data, key, iv) -> bytes`
رمزگشایی AES-256-IGE با همان پارامترهای بالا.

### `ctr256_crypt(data, key, iv, offset=0) -> bytes`
رمزنگاری و رمزگشایی جریانی AES-256-CTR (بدون محدودیت طول داده).
- `key`: کلید ۳۲ بایتی
- `iv`: شمارندهٔ اولیه ۱۶ بایتی
- `offset`: جابه‌جایی بایتی در جریان کلید (عالی برای آپلود و دانلود موازی تکه‌های فایل)

### `cbc256_encrypt(data, key, iv) -> bytes` و `cbc256_decrypt(data, key, iv) -> bytes`
رمزنگاری و رمزگشایی AES-256-CBC (طول `data` مضرب ۱۶، `key` ۳۲ بایتی، `iv` ۱۶ بایتی).

### `compute_msg_key(auth_key, padded_plaintext, from_client=True) -> bytes`
محاسبهٔ `msg_key` شانزده‌بایتی مطابق استاندارد MTProto 2.0 از `auth_key` ۲۵۶ بایتی و دادهٔ پدشده.

### `mtproto2_kdf(auth_key, msg_key, from_client=True) -> tuple[bytes, bytes]`
استخراج زوج `(aes_key, aes_iv)` (هر کدام ۳۲ بایت) مطابق استاندارد KDF در MTProto 2.0.

---

## اتصال به `shirdal`

در `shirdal/mtproto/crypto.py` می‌توانید به‌سادگی `shircrypt` را اولویت دهید:

```python
try:
    from shircrypt import ige256_decrypt as aes_ige_decrypt
    from shircrypt import ige256_encrypt as aes_ige_encrypt
    from shircrypt import mtproto2_kdf as kdf_mtproto2
except ImportError:
    ...
```

</div>
