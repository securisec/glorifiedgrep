from pathlib import Path

from glorifiedgrep import GlorifiedAndroid

test_dir = Path()
test_apk = test_dir / "tests" / "test.apk"

g = GlorifiedAndroid(test_apk.resolve(), output_dir="/tmp/ggtest")


def test_manifest_activities():
    assert len(g.manifest_activities()) == 1


def test_manifest_activity_alias():
    assert len(g.manifest_activity_alias()) == 0


def test_manifest_allow_backup():
    assert g.manifest_allow_backup() == True


def test_manifest_android_version():
    assert len(g.manifest_android_version()) == 2


def test_manifest_application_node():
    assert len(g.manifest_application_node()) == 7


def test_manifest_bind_permissions():
    assert len(g.manifest_bind_permissions()) == 0


def test_manifest_custom_permission():
    assert len(g.manifest_custom_permission()) == 0


def test_manifest_dangerous_permission():
    assert len(g.manifest_dangerous_permission()) == 0


def test_manifest_debuggable():
    assert g.manifest_debuggable() == False


def test_manifest_exported_providers():
    assert len(g.manifest_exported_providers()) == 0


def test_manifest_intent_uri_filter():
    assert len(g.manifest_intent_uri_filter()) == 1


def test_manifest_main_activity():
    assert len(g.manifest_main_activity()) == 2


def test_manifest_meta_data():
    assert len(g.manifest_meta_data()) == 0


def test_manifest_min_sdk():
    assert g.manifest_min_sdk() == 19


def test_manifest_package_name():
    assert g.manifest_package_name() == "owasp.mstg.uncrackable3"


def test_manifest_permission():
    assert len(g.manifest_permission()) == 0


def test_manifest_platform_build_version_code():
    assert g.manifest_platform_build_version_code() == 28


def test_manifest_platform_build_version_name():
    assert g.manifest_platform_build_version_name() == "28"


def test_manifest_providers():
    assert len(g.manifest_providers()) == 0


def test_manifest_receivers():
    assert len(g.manifest_receivers()) == 0


def test_manifest_secrets():
    assert len(g.manifest_secrets()) == 0


def test_manifest_services():
    assert len(g.manifest_services()) == 0


def test_manifest_signature_permission():
    assert len(g.manifest_signature_permission()) == 0


def test_manifest_target_sdk():
    assert g.manifest_target_sdk() == 28


def test_manifest_uses_configuration():
    assert g.manifest_uses_configuration() == None


def test_manifest_uses_feature():
    assert len(g.manifest_uses_feature()) == 0


def test_manifest_uses_library():
    assert g.manifest_uses_library() == None


def test_manifest_uses_permission():
    assert len(g.manifest_uses_permission()) == 0


def test_manifest_version_code():
    assert g.manifest_version_code() == 1


def test_manifest_version_name():
    assert len(g.manifest_version_name()) == 3
