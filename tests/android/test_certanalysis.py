from pathlib import Path

from glorifiedgrep import GlorifiedAndroid

test_dir = Path()
test_apk = test_dir / "tests" / "test.apk"

g = GlorifiedAndroid(test_apk.resolve(), output_dir="/tmp/ggtest")


def test_cert_public_key():
    assert g.cert_public_key().count == 1


def test_cert_certificate():
    assert g.cert_certificate().count == 1


def test_cert_digest():
    assert g.cert_digest()["md5"] == b"3E:D3:56:CC:5E:5B:13:B1:A0:9B:52:F3:98:7C:39:D7"


def test_cert_issuer():
    assert g.cert_issuer().count == 4


def test_cert_valid_dates():
    assert len(g.cert_valid_dates()) == 3


def test_cert_serial_number():
    assert g.cert_serial_number() == 43880535


def test_cert_signature_algorithm():
    assert g.cert_signature_algorithm() == b"sha256WithRSAEncryption"


def test_cert_version():
    assert g.cert_version() == 2


def test_cert_bits():
    assert g.cert_bits() == 2048


def test_cert_subject():
    assert len(g.cert_subject()) == 4
