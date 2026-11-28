import hashlib
import os
import unittest

import shircrypt


class TestShircrypt(unittest.TestCase):
    def test_ige256_roundtrip_and_buffers(self) -> None:
        key = os.urandom(32)
        iv = os.urandom(32)
        for length in (0, 16, 48, 4096, 16384):
            plain = os.urandom(length)
            ct = shircrypt.ige256_encrypt(plain, key, iv)
            self.assertEqual(len(ct), length)
            if length > 0:
                self.assertNotEqual(ct, plain)
            pt = shircrypt.ige256_decrypt(memoryview(ct), bytearray(key), memoryview(iv))
            self.assertEqual(pt, plain)

    def test_ige256_garble_propagation(self) -> None:
        key = b"\x11" * 32
        iv = b"\x22" * 32
        plain = b"A" * 64
        ct = bytearray(shircrypt.ige256_encrypt(plain, key, iv))
        ct[0] ^= 0xFF
        pt = shircrypt.ige256_decrypt(bytes(ct), key, iv)
        self.assertNotEqual(pt[:16], plain[:16])
        self.assertNotEqual(pt[48:], plain[48:])

    def test_ctr256_roundtrip_and_offset(self) -> None:
        key = os.urandom(32)
        iv = os.urandom(16)
        full = os.urandom(100)
        ct_full = shircrypt.ctr256_crypt(full, key, iv)
        self.assertEqual(shircrypt.ctr256_crypt(ct_full, key, iv), full)

        # Streaming chunk at offset=37 must match full stream slice
        ct_chunk = shircrypt.ctr256_crypt(full[37:89], key, iv, offset=37)
        self.assertEqual(ct_chunk, ct_full[37:89])

    def test_cbc256_roundtrip(self) -> None:
        key = os.urandom(32)
        iv = os.urandom(16)
        plain = os.urandom(256)
        ct = shircrypt.cbc256_encrypt(plain, key, iv)
        self.assertNotEqual(ct, plain)
        self.assertEqual(shircrypt.cbc256_decrypt(ct, key, iv), plain)

    def test_mtproto2_kdf_and_msg_key(self) -> None:
        auth_key = bytes(i % 256 for i in range(256))
        padded = b"mtproto-2.0-payload-16b!" + b"\x00" * 8
        for from_client in (True, False):
            x = 0 if from_client else 8
            expected_mk = hashlib.sha256(auth_key[88 + x : 88 + x + 32] + padded).digest()[8:24]
            mk = shircrypt.compute_msg_key(auth_key, padded, from_client=from_client)
            self.assertEqual(mk, expected_mk)

            sha_a = hashlib.sha256(mk + auth_key[x : x + 36]).digest()
            sha_b = hashlib.sha256(auth_key[40 + x : 40 + x + 36] + mk).digest()
            expected_key = sha_a[0:8] + sha_b[8:24] + sha_a[24:32]
            expected_iv = sha_b[0:8] + sha_a[8:24] + sha_b[24:32]
            aes_key, aes_iv = shircrypt.mtproto2_kdf(auth_key, mk, from_client=from_client)
            self.assertEqual(aes_key, expected_key)
            self.assertEqual(aes_iv, expected_iv)

    def test_validation_errors(self) -> None:
        with self.assertRaises(ValueError):
            shircrypt.ige256_encrypt(b"0" * 16, b"short", b"0" * 32)
        with self.assertRaises(ValueError):
            shircrypt.ige256_encrypt(b"0" * 16, b"0" * 32, b"short")
        with self.assertRaises(ValueError):
            shircrypt.ige256_encrypt(b"not-aligned", b"0" * 32, b"0" * 32)
        with self.assertRaises(ValueError):
            shircrypt.ctr256_crypt(b"abc", b"0" * 32, b"short-iv")
        with self.assertRaises(ValueError):
            shircrypt.cbc256_encrypt(b"123", b"0" * 32, b"0" * 16)
        with self.assertRaises(ValueError):
            shircrypt.mtproto2_kdf(b"short", b"0" * 16)
        with self.assertRaises(ValueError):
            shircrypt.mtproto2_kdf(b"0" * 256, b"short")



    def test_mtproto2_packet_fused_roundtrip(self) -> None:
        auth_key = bytes((i * 7) % 256 for i in range(256))
        padded = os.urandom(512)
        for from_client in (True, False):
            mk, ct = shircrypt.mtproto2_encrypt_packet(auth_key, padded, from_client=from_client)
            self.assertEqual(len(mk), 16)
            self.assertEqual(len(ct), len(padded))
            pt = shircrypt.mtproto2_decrypt_packet(auth_key, mk, ct, from_client=from_client)
            self.assertEqual(pt, padded)
            bad_mk = bytes([mk[0] ^ 0xFF]) + mk[1:]
            with self.assertRaises(ValueError):
                shircrypt.mtproto2_decrypt_packet(auth_key, bad_mk, ct, from_client=from_client)



    def test_native_auth_key_seal_and_open(self) -> None:
        key = bytes((i * 13) % 256 for i in range(256))
        nk = shircrypt.NativeAuthKey(key)
        self.assertEqual(nk.key, key)
        self.assertEqual(len(nk.key_id_bytes), 8)
        self.assertEqual(len(nk.aux_hash), 8)
        for from_client in (True, False):
            for size in (0, 32, 127, 5000):
                inner = os.urandom(size)
                pkt = nk.seal_packet(inner, from_client=from_client)
                self.assertEqual(pkt[:8], nk.key_id_bytes)
                self.assertEqual((len(pkt) - 24) % 16, 0)
                opened = nk.open_packet(pkt, from_client=from_client)
                self.assertTrue(opened.startswith(inner))
                self.assertGreaterEqual(len(opened) - len(inner), 12)
        with self.assertRaises(ValueError):
            nk.open_packet(b"\x00" * 40, from_client=False)
        pkt = nk.seal_packet(b"hello-shirdal", from_client=True)
        bad_pkt = pkt[:8] + bytes([pkt[8] ^ 0xFF]) + pkt[9:]
        with self.assertRaises(ValueError):
            nk.open_packet(bad_pkt, from_client=True)

    def test_factorize_pq(self) -> None:
        self.assertEqual(shircrypt.factorize_pq(179424673 * 179424691), (179424673, 179424691))
        self.assertEqual(shircrypt.factorize_pq(14), (2, 7))
        with self.assertRaises(ValueError):
            shircrypt.factorize_pq(1)

if __name__ == "__main__":
    unittest.main()
