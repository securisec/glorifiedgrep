from pathlib import Path

from glorifiedgrep import GlorifiedAndroid

test_dir = Path()
test_apk = test_dir / "tests" / "test.apk"

g = GlorifiedAndroid(test_apk.resolve(), output_dir="/tmp/ggtest")


def test_code_accessibility_service():
    assert g.code_accessibility_service().count == 219


def test_code_add_javascriptinterface():
    assert g.code_add_javascriptinterface().count == 0


def test_code_android_contacts_content_provider():
    assert g.code_android_contacts_content_provider().count == 0


def test_code_apache_http_get_request():
    assert g.code_apache_http_get_request().count == 0


def test_code_apache_http_other_request_methods():
    assert g.code_apache_http_other_request_methods().count == 0


def test_code_apache_http_post_request():
    assert g.code_apache_http_post_request().count == 0


# def test_code_api_builder():
#     assert g.code_api_builder().count == 59


def test_code_apk_files():
    assert g.code_apk_files().count == 1


def test_code_aws_query():
    assert g.code_aws_query().count == 0


def test_code_base64_decode():
    assert g.code_base64_decode().count == 1


def test_code_base64_encode():
    assert g.code_base64_encode().count == 1


def test_code_boot_completed_persistance():
    assert g.code_boot_completed_persistance().count == 0


def test_code_broadcast_messages():
    assert g.code_broadcast_messages().count == 5


def test_code_broadcast_send():
    assert g.code_broadcast_send().count == 6


def test_code_browser_db_access():
    assert g.code_browser_db_access().count == 0


def test_code_byte_constants():
    assert g.code_byte_constants().count == 1


def test_code_call_log():
    assert g.code_call_log().count == 0


def test_code_camera_access():
    assert g.code_camera_access().count == 1


def test_code_cipher_instance():
    assert g.code_cipher_instance().count == 0


def test_code_clipboard_manager():
    assert g.code_clipboard_manager().count == 1


def test_code_command_exec():
    assert g.code_command_exec().count == 0


def test_code_cookies():
    assert g.code_cookies().count == 0


def test_code_create_new_file():
    assert g.code_create_new_file().count == 2


def test_code_create_sockets():
    assert g.code_create_sockets().count == 0


def test_code_create_tempfile():
    assert g.code_create_tempfile().count == 0


def test_code_database_interaction():
    assert g.code_database_interaction().count == 22


def test_code_database_query():
    assert g.code_database_query().count == 11


def test_code_debuggable_check():
    assert g.code_debuggable_check().count == 1


def test_code_debugger_check():
    assert g.code_debugger_check().count == 1


def test_code_deserialization():
    assert g.code_deserialization().count == 0


def test_code_device_id():
    assert g.code_device_id().count == 3


def test_code_device_serial_number():
    assert g.code_device_serial_number().count == 0


def test_code_download_manager():
    assert g.code_download_manager().count == 1


def test_code_dynamic_dexclassloader():
    assert g.code_dynamic_dexclassloader().count == 0


def test_code_dynamic_other_classloader():
    assert g.code_dynamic_other_classloader().count == 0


def test_code_external_file_access():
    assert g.code_external_file_access().count == 6


def test_code_file_observer():
    assert g.code_file_observer().count == 0


def test_code_file_read():
    assert g.code_file_read().count == 3


def test_code_file_write():
    assert g.code_file_write().count == 0


def test_code_find_intents():
    assert g.code_find_intents().count == 13


def test_code_firebase_imports():
    assert g.code_firebase_imports().count == 0


def test_code_get_environment_var():
    assert g.code_get_environment_var().count == 1


def test_code_gps_location():
    assert g.code_gps_location().count == 6


def test_code_hashing_algorithms():
    assert g.code_hashing_algorithms().count == 0


def test_code_hashing_custom():
    assert g.code_hashing_custom().count == 0


def test_code_http_request_methods():
    assert g.code_http_request_methods().count == 0


def test_code_intent_filters():
    assert g.code_intent_filters().count == 29


def test_code_intent_parameters():
    assert g.code_intent_parameters().count == 4


def test_code_invisible_elements():
    assert g.code_invisible_elements().count == 3


def test_code_jar_urlconnection():
    assert g.code_jar_urlconnection().count == 0


def test_code_key_generator():
    assert g.code_key_generator().count == 0


def test_code_keystore_files():
    assert g.code_keystore_files().count == 0


def test_code_load_native_library():
    assert g.code_load_native_library().count == 1


def test_code_location():
    assert g.code_location().count == 6


def test_code_location_manager():
    assert g.code_location_manager().count == 7


def test_code_logging():
    assert g.code_logging().count == 321


def test_code_make_http_request():
    assert g.code_make_http_request().count == 0


def test_code_make_https_request():
    assert g.code_make_https_request().count == 0


def test_code_mediastore():
    assert g.code_mediastore().count == 0


def test_code_notification_manager():
    assert g.code_notification_manager().count == 30


def test_code_null_cipher():
    assert g.code_null_cipher().count == 0


def test_code_object_deserialization():
    assert g.code_object_deserialization().count == 1


def test_code_parse_uri():
    assert g.code_parse_uri().count == 7


def test_code_password_finder():
    assert g.code_password_finder().count == 0


def test_code_phone_sensors():
    assert g.code_phone_sensors().count == 0


def test_code_read_sms_messages():
    assert g.code_read_sms_messages().count == 0


def test_code_reflection():
    assert g.code_reflection().count == 316


def test_code_regex_matcher():
    assert g.code_regex_matcher().count == 8


def test_code_regex_pattern():
    assert g.code_regex_pattern().count == 13


def test_code_root_access():
    assert g.code_root_access().count == 1


def test_code_screenshots():
    assert g.code_screenshots().count == 130


def test_code_sdcard():
    assert g.code_sdcard().count == 0


def test_code_send_sms_text():
    assert g.code_send_sms_text().count == 0


def test_code_services():
    assert g.code_services().count == 6


def test_code_shared_preferences():
    assert g.code_shared_preferences().count == 2


def test_code_sim_information():
    assert g.code_sim_information().count == 0


def test_code_sql_injection_points():
    assert g.code_sql_injection_points().count == 0


def test_code_sql_injection_user_input():
    assert g.code_sql_injection_user_input().count == 0


def test_code_sql_java_implementation():
    assert g.code_sql_java_implementation().count == 4


def test_code_sql_query_other():
    assert g.code_sql_query_other().count == 0


def test_code_sql_select_raw_query():
    assert g.code_sql_select_raw_query().count == 0


def test_code_sqlcipher_password():
    assert g.code_sqlcipher_password().count == 0


def test_code_sqlite_operations():
    assert g.code_sqlite_operations().count == 0


def test_code_ssl_connections():
    assert g.code_ssl_connections().count == 0


def test_code_stack_trace():
    assert g.code_stack_trace().count == 5


def test_code_static_iv():
    assert g.code_static_iv().count == 0


def test_code_string_constants():
    assert g.code_string_constants().count == 369


def test_code_stub_packed():
    assert g.code_stub_packed().count == 0


def test_code_system_service():
    assert g.code_system_service().count == 48


def test_code_tcp_sockets():
    assert g.code_tcp_sockets().count == 0


def test_code_trust_all_ssl():
    assert g.code_trust_all_ssl().count == 0


def test_code_udp_sockets():
    assert g.code_udp_sockets().count == 11


def test_code_weak_hashing():
    assert g.code_weak_hashing().count == 0


def test_code_websocket_usage():
    assert g.code_websocket_usage().count == 0


def test_code_webview_content_access():
    assert g.code_webview_content_access().count == 0


def test_code_webview_database():
    assert g.code_webview_database().count == 0


def test_code_webview_debug_enabled():
    assert g.code_webview_debug_enabled().count == 0


def test_code_webview_file_access():
    assert g.code_webview_file_access().count == 0


def test_code_webview_get_request():
    assert g.code_webview_get_request().count == 0


def test_code_webview_js_enabled():
    assert g.code_webview_js_enabled().count == 0


def test_code_webview_post_request():
    assert g.code_webview_post_request().count == 0


def test_code_xml_processor():
    assert g.code_xml_processor().count == 0


def test_code_xor_encryption():
    assert g.code_xor_encryption().count == 9


def test_code_xpath():
    assert g.code_xpath().count == 0


def test_code_package_installed():
    assert g.code_package_installed().count == 0


def test_code_system_file_exists():
    assert g.code_system_file_exists().count == 2


def test_code_imports():
    assert len(g.code_imports("R")) == 86


def test_code_class_init():
    assert g.code_class_init("StringBuilder").count == 4


def test_code_exif_data():
    assert g.code_exif_data("StringBuilder").count == 0


def test_code_class_extends():
    assert g.code_class_extends().count == 328
