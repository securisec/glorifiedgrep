from pathlib import Path

from glorifiedgrep import GlorifiedAndroid

test_dir = Path()
test_apk = test_dir / "tests" / "test.apk"

g = GlorifiedAndroid(test_apk.resolve(), output_dir="/tmp/ggtest")


def test_owasp_cloud_backup():
    assert g.owasp_cloud_backup().count == 0


def test_owasp_code_check_permission():
    assert g.owasp_code_check_permission().count == 1


def test_owasp_crypto_imports():
    assert g.owasp_crypto_imports().count == 1


def test_owasp_crypto_primitives():
    assert g.owasp_crypto_primitives().count == 0


def test_owasp_debug_code():
    assert g.owasp_debug_code().count == 5


def test_owasp_encrypted_sql_db():
    assert g.owasp_encrypted_sql_db().count == 0


def test_owasp_external_cache_dir():
    assert g.owasp_external_cache_dir().count == 2


def test_owasp_external_storage():
    assert g.owasp_external_storage().count == 7


def test_owasp_get_secret_keys():
    assert g.owasp_get_secret_keys().count == 0


def test_owasp_hardcoded_keys():
    assert g.owasp_hardcoded_keys().count == 0


def test_owasp_insecure_fingerprint_auth():
    assert g.owasp_insecure_fingerprint_auth().count == 0


def test_owasp_insecure_random():
    assert g.owasp_insecure_random().count == 0


def test_owasp_intent_parameter():
    assert g.owasp_intent_parameter().count == 0


def test_owasp_keychain_password():
    assert g.owasp_keychain_password().count == 0


def test_owasp_keystore_cert_pinning():
    assert g.owasp_keystore_cert_pinning().count == 0


def test_owasp_properly_signed():
    assert g.owasp_properly_signed().count == 1


def test_owasp_runtime_exception_handling():
    assert g.owasp_runtime_exception_handling().count == 744


def test_owasp_ssl_no_hostname_verification():
    assert g.owasp_ssl_no_hostname_verification().count == 0


def test_owasp_webview_cert_pinning():
    assert g.owasp_webview_cert_pinning().count == 0


def test_owasp_webview_loadurl():
    assert g.owasp_webview_loadurl().count == 0


def test_owasp_webview_native_function():
    assert g.owasp_webview_native_function().count == 0


def test_owasp_webview_ssl_ignore():
    assert g.owasp_webview_ssl_ignore().count == 0


def test_owasp_world_read_write_files():
    assert g.owasp_world_read_write_files().count == 0
