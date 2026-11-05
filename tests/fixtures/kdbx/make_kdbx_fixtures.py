"""Generate KeePass test databases for VaultRust's importer tests.

Uses pykeepass (an independent KDBX implementation) so the Rust importer is
tested against files it did not write itself. All data is fictional.
Usage: python make_kdbx_fixtures.py <output dir>
"""
import os
import sys
import time

from construct import Container
from pykeepass import create_database
from pykeepass.kdbx_parsing.kdbx3 import DynamicHeader as DH3  # noqa: F401

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
PW = "fixture password"

ARGON2ID = bytes.fromhex("9e298b1956db4773b23dfc3ec6f0a1e6")
AES_KDF4 = bytes.fromhex("c9d9f39a628a4460bf740d08c18a4fea")


def populate(kp):
    root = kp.root_group
    work = kp.add_group(root, "Work")
    servers = kp.add_group(work, "Servers")
    e = kp.add_entry(root, "Example Mail", "alice@example.com", "first password",
                     url="https://mail.example.com", notes="Line one\nLine two")
    e.password = "second password"
    kp.save()
    e.save_history()
    e.password = "current mail password"
    e.otp = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    e.tags = ["personal", "email"]
    e.set_custom_property("Recovery code", "ABCD-EFGH", protect=True)
    e.set_custom_property("Account no", "12345", protect=False)
    kp.add_entry(work, "Intranet", "alice", "intranet pw ünïcødé", url="https://intranet.example")
    kp.add_entry(servers, "db01", "root", "server pw", notes="ssh root@db01")
    note = kp.add_entry(root, "Wi-Fi codes", "", "", notes="guest: 1234")
    note.password = ""
    trashed = kp.add_entry(root, "Old thing", "bob", "deleted pw")
    kp.trash_entry(trashed)


def save_kdbx4(name, cipher=None, kdf=None):
    path = os.path.join(out, name)
    kp = create_database(path, password=PW)
    populate(kp)
    h = kp.kdbx.header.value.dynamic_header
    if cipher == "chacha20":
        h.cipher_id.data = "chacha20"
        h.encryption_iv.data = os.urandom(12)
    if kdf == "argon2id":
        h.kdf_parameters.data.dict["$UUID"].value = ARGON2ID
    if kdf == "aes":
        d = h.kdf_parameters.data.dict
        for k in ["I", "M", "P", "V"]:
            del d[k]
        d["$UUID"].value = AES_KDF4
        d["R"] = Container(type=5, key="R", value=6000, next_byte=0)
        d["S"].value = os.urandom(32)
    kp.save()
    return path


def save_kdbx3(name):
    path = os.path.join(out, name)
    kp = create_database(path, password=PW)
    populate(kp)
    hv = kp.kdbx.header.value
    hv.major_version = 3
    hv.minor_version = 1

    def item(i, data):
        return Container(id=i, data=data)

    hv.dynamic_header = Container(
        cipher_id=item("cipher_id", "aes256"),
        compression_flags=item("compression_flags", Container(compression=True)),
        master_seed=item("master_seed", os.urandom(32)),
        transform_seed=item("transform_seed", os.urandom(32)),
        transform_rounds=item("transform_rounds", 6000),
        encryption_iv=item("encryption_iv", os.urandom(16)),
        protected_stream_key=item("protected_stream_key", os.urandom(32)),
        stream_start_bytes=item("stream_start_bytes", os.urandom(32)),
        protected_stream_id=item("protected_stream_id", "salsa20"),
        end=item("end", b"\r\n\r\n"),
    )
    kp.kdbx.body = Container(payload=Container(xml=kp.tree))
    from pykeepass.kdbx_parsing.kdbx import KDBX
    KDBX.build_file(kp.kdbx, path, password=PW, keyfile=None, transformed_key=None, decrypt=True)
    return path


paths = [
    save_kdbx4("kdbx4-aes-argon2d.kdbx"),
    save_kdbx4("kdbx4-chacha20-argon2id.kdbx", cipher="chacha20", kdf="argon2id"),
    save_kdbx4("kdbx4-aes-aeskdf.kdbx", kdf="aes"),
    save_kdbx3("kdbx3-aes-salsa20.kdbx"),
]

# Verify every file opens again with pykeepass and has the expected data.
from pykeepass import PyKeePass  # noqa: E402

for p in paths:
    kp = PyKeePass(p, password=PW)
    titles = sorted(e.title for e in kp.entries)
    mail = kp.find_entries(title="Example Mail", first=True)
    print(os.path.basename(p), kp.version, kp.encryption_algorithm, kp.kdf_algorithm,
          titles, mail.password, len(mail.history), mail.otp is not None)
