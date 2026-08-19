#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import os
import threading
import stat
import hashlib
import base64
import zlib
from enum import IntEnum
from typing import Optional

from . import ecc
from .util import (profiler, InvalidPassword, WalletFileException, bfh, standardize_path,
                   test_read_write_permissions, os_chmod)

from .wallet_db import WalletDB
from .logging import Logger

SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 64
SCRYPT_SALT_LEN = 16
SCRYPT_MAXMEM = 64 * 1024 * 1024


def get_derivation_used_for_hw_device_encryption():
    return ("m"
            "/4541509'"      # ascii 'ELE'  as decimal ("BIP43 purpose")
            "/1112098098'")  # ascii 'BIE2' as decimal


class StorageEncryptionVersion(IntEnum):
    PLAINTEXT = 0
    USER_PASSWORD = 1          # legacy BIE1; readable and auto-migrated
    XPUB_PASSWORD = 2          # BIE2 hardware-derived secret
    USER_PASSWORD_SCRYPT = 3   # BIE3; default for new human passwords


class StorageReadWriteError(Exception): pass


# TODO: Rename to Storage
class WalletStorage(Logger):

    def __init__(self, path):
        Logger.__init__(self)
        self.path = standardize_path(path)
        self._file_exists = bool(self.path and os.path.exists(self.path))
        self.logger.info(f"wallet path {self.path}")
        self.pubkey = None
        self.decrypted = ''
        self._kdf_salt = None
        try:
            test_read_write_permissions(self.path)
        except IOError as e:
            raise StorageReadWriteError(e) from e
        if self.file_exists():
            with open(self.path, "r", encoding='utf-8') as f:
                self.raw = f.read()
            self._encryption_version = self._init_encryption_version()
        else:
            self.raw = ''
            self._encryption_version = StorageEncryptionVersion.PLAINTEXT

    def read(self):
        return self.decrypted if self.is_encrypted() else self.raw

    def write(self, data: str) -> None:
        s = self.encrypt_before_writing(data)
        temp_path = "%s.tmp.%s" % (self.path, os.getpid())
        with open(temp_path, "w", encoding='utf-8') as f:
            f.write(s)
            f.flush()
            os.fsync(f.fileno())

        try:
            mode = os.stat(self.path).st_mode
        except FileNotFoundError:
            mode = stat.S_IREAD | stat.S_IWRITE

        # assert that wallet file does not exist, to prevent wallet corruption (see issue #5082)
        if not self.file_exists():
            assert not os.path.exists(self.path)
        os.replace(temp_path, self.path)
        os_chmod(self.path, mode)
        self._file_exists = True
        self.raw = s
        self.logger.info(f"saved {self.path}")

    def file_exists(self) -> bool:
        return self._file_exists

    def is_past_initial_decryption(self) -> bool:
        """Return if storage is in a usable state for normal operations.

        The value is True exactly
            if encryption is disabled completely (self.is_encrypted() == False),
            or if encryption is enabled but the contents have already been decrypted.
        """
        return not self.is_encrypted() or bool(self.pubkey)

    def is_encrypted(self) -> bool:
        """Return if storage encryption is currently enabled."""
        return self.get_encryption_version() != StorageEncryptionVersion.PLAINTEXT

    def is_encrypted_with_user_pw(self) -> bool:
        return self.get_encryption_version() in (
            StorageEncryptionVersion.USER_PASSWORD,
            StorageEncryptionVersion.USER_PASSWORD_SCRYPT,
        )

    def is_encrypted_with_hw_device(self) -> bool:
        return self.get_encryption_version() == StorageEncryptionVersion.XPUB_PASSWORD

    def get_encryption_version(self):
        """Return the version of encryption used for this storage.

        0: plaintext / no encryption

        ECIES, private key derived from a password,
        1: legacy user password (BIE1; migrated after unlock)
        2: password is derived from an xpub; used with hw wallets
        3: user password with random-salt scrypt KDF (BIE3)
        """
        return self._encryption_version

    def _init_encryption_version(self):
        try:
            decoded = base64.b64decode(self.raw)
            magic = decoded[0:4]
            if magic == b'BIE1':
                return StorageEncryptionVersion.USER_PASSWORD
            elif magic == b'BIE2':
                return StorageEncryptionVersion.XPUB_PASSWORD
            elif magic == b'BIE3':
                if len(decoded) < 4 + SCRYPT_SALT_LEN + 85:
                    raise WalletFileException("invalid BIE3 wallet envelope")
                self._kdf_salt = decoded[4:4 + SCRYPT_SALT_LEN]
                return StorageEncryptionVersion.USER_PASSWORD_SCRYPT
            else:
                return StorageEncryptionVersion.PLAINTEXT
        except WalletFileException:
            raise
        except Exception:
            return StorageEncryptionVersion.PLAINTEXT

    @staticmethod
    def get_eckey_from_password(password):
        """Legacy BIE1/BIE2 KDF. Never use for new human-password files."""
        if password is None:
            password = ""
        secret = hashlib.pbkdf2_hmac(
            'sha512', password.encode('utf-8'), b'', iterations=1024
        )
        return ecc.ECPrivkey.from_arbitrary_size_secret(secret)

    @staticmethod
    def get_eckey_from_password_scrypt(password, salt: bytes):
        if password is None:
            password = ""
        if not isinstance(salt, bytes) or len(salt) != SCRYPT_SALT_LEN:
            raise WalletFileException("invalid BIE3 KDF salt")
        secret = hashlib.scrypt(
            password.encode('utf-8'), salt=salt,
            n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
            dklen=SCRYPT_DKLEN, maxmem=SCRYPT_MAXMEM,
        )
        return ecc.ECPrivkey.from_arbitrary_size_secret(secret)

    def _get_eckey_for_password(self, password):
        if self._encryption_version == StorageEncryptionVersion.USER_PASSWORD_SCRYPT:
            if self._kdf_salt is None:
                raise WalletFileException("BIE3 KDF salt unavailable")
            return self.get_eckey_from_password_scrypt(password, self._kdf_salt)
        return self.get_eckey_from_password(password)

    def _decode_bie3_envelope(self):
        try:
            decoded = base64.b64decode(self.raw)
        except Exception as e:
            raise WalletFileException("invalid BIE3 wallet envelope") from e
        if decoded[:4] != b'BIE3' or len(decoded) < 4 + SCRYPT_SALT_LEN + 85:
            raise WalletFileException("invalid BIE3 wallet envelope")
        salt = decoded[4:4 + SCRYPT_SALT_LEN]
        inner = base64.b64encode(decoded[4 + SCRYPT_SALT_LEN:])
        return salt, inner

    def _get_encryption_magic(self):
        v = self._encryption_version
        if v == StorageEncryptionVersion.USER_PASSWORD:
            return b'BIE1'
        elif v == StorageEncryptionVersion.XPUB_PASSWORD:
            return b'BIE2'
        elif v == StorageEncryptionVersion.USER_PASSWORD_SCRYPT:
            return b'BIE3'
        else:
            raise WalletFileException('no encryption magic for version: %s' % v)

    def decrypt(self, password) -> None:
        """Raise InvalidPassword for a bad password and migrate BIE1 to BIE3."""
        if self.is_past_initial_decryption():
            return
        original_version = self._encryption_version
        if original_version == StorageEncryptionVersion.USER_PASSWORD_SCRYPT:
            salt, inner = self._decode_bie3_envelope()
            self._kdf_salt = salt
            ec_key = self._get_eckey_for_password(password)
            s = zlib.decompress(ec_key.decrypt_message(inner, b'BIE3')).decode('utf8')
        else:
            ec_key = self._get_eckey_for_password(password)
            if self.raw:
                enc_magic = self._get_encryption_magic()
                s = zlib.decompress(ec_key.decrypt_message(self.raw, enc_magic)).decode('utf8')
            else:
                s = ''
        self.pubkey = ec_key.get_public_key_hex()
        self.decrypted = s

        if original_version == StorageEncryptionVersion.USER_PASSWORD:
            self._kdf_salt = os.urandom(SCRYPT_SALT_LEN)
            self._encryption_version = StorageEncryptionVersion.USER_PASSWORD_SCRYPT
            migrated_key = self._get_eckey_for_password(password)
            self.pubkey = migrated_key.get_public_key_hex()
            self.write(self.decrypted)
            self.logger.info("migrated legacy BIE1 wallet encryption to BIE3")

    def encrypt_before_writing(self, plaintext: str) -> str:
        s = plaintext
        if self.pubkey:
            c = zlib.compress(bytes(s, 'utf8'), level=zlib.Z_BEST_SPEED)
            enc_magic = self._get_encryption_magic()
            public_key = ecc.ECPubkey(bfh(self.pubkey))
            inner = public_key.encrypt_message(c, enc_magic)
            if self._encryption_version == StorageEncryptionVersion.USER_PASSWORD_SCRYPT:
                if self._kdf_salt is None or len(self._kdf_salt) != SCRYPT_SALT_LEN:
                    raise WalletFileException("BIE3 KDF salt unavailable")
                envelope = b'BIE3' + self._kdf_salt + base64.b64decode(inner)
                s = base64.b64encode(envelope).decode('ascii')
            else:
                s = inner.decode('utf8')
        return s

    def check_password(self, password: Optional[str]) -> None:
        """Raises an InvalidPassword exception on invalid password"""
        if not self.is_encrypted():
            if password is not None:
                raise InvalidPassword("password given but wallet has no password")
            return
        if not self.is_past_initial_decryption():
            self.decrypt(password)  # this sets self.pubkey
        assert self.pubkey is not None
        if self.pubkey != self._get_eckey_for_password(password).get_public_key_hex():
            raise InvalidPassword()

    def set_password(self, password, enc_version=None):
        """Set storage encryption; legacy USER_PASSWORD requests become BIE3."""
        if not self.is_past_initial_decryption():
            raise Exception("storage needs to be decrypted before changing password")
        if enc_version is None:
            enc_version = self._encryption_version
        enc_version = StorageEncryptionVersion(enc_version)
        if enc_version == StorageEncryptionVersion.USER_PASSWORD:
            enc_version = StorageEncryptionVersion.USER_PASSWORD_SCRYPT
        if password and enc_version != StorageEncryptionVersion.PLAINTEXT:
            self._encryption_version = enc_version
            if enc_version == StorageEncryptionVersion.USER_PASSWORD_SCRYPT:
                self._kdf_salt = os.urandom(SCRYPT_SALT_LEN)
            else:
                self._kdf_salt = None
            ec_key = self._get_eckey_for_password(password)
            self.pubkey = ec_key.get_public_key_hex()
        else:
            self.pubkey = None
            self._kdf_salt = None
            self._encryption_version = StorageEncryptionVersion.PLAINTEXT

    def basename(self) -> str:
        return os.path.basename(self.path)

