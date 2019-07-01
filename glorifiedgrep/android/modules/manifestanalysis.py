import hashlib
import json
import re

import xmltodict

from .androidcore import _AndroidCore
from ...logger import _logger
from .constants import _AppAnalysisConstants


class _ManifestAnalysis(_AndroidCore, _AppAnalysisConstants):

    def _parse_manifest_xml(self):
        """
        Loads and returns a dict object from the AndroidManifest.xml file
        :return: Dict converted from XML
        :rtype: object
        """
        namespace = {'http://schemas.android.com/apk/res/android': ''}
        try:
            with open(self._manifest_path, 'r') as f:
                data = json.dumps(xmltodict.parse(f.read(), process_namespaces=True,
                                                  namespaces=namespace, attr_prefix=''))
                self.log_debug('')
            return json.loads(data)['manifest']
        except FileNotFoundError as e:
            self.log_exception('AndroidManifest.xml not found')
            raise

    def all_manifest_analysis(self) -> dict:
        """
        Property runs all available checks in _ManifestAnalysis

        :return: Dictionary of all analysis
        :rtype: dict
        """
        methods = [p for p in vars(
            _ManifestAnalysis).keys() if not p.startswith('_')]
        [getattr(self, m)() for m in methods if m != 'all_manifest_analysis']
        self.log_debug('')
        return self._android_findings['manifest_analysis']

    @_logger
    def manifest_package_name(self) -> list:
        """
        Returns the package name of the APK
        | `Reference <https://developer.android.com/guide/topics/manifest/manifest-element>`__

        :return: package name
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_package_name()
        """
        p = self._parse_manifest_xml()['package']
        self._manifest_analysis['package_name'] = [p]
        self.log_debug('')
        return [p]

    @_logger
    def manifest_version_name(self) -> list:
        """
        Returns the version name from the APK
        | `Reference <https://developer.android.com/guide/topics/manifest/manifest-element>`__

        :return: version name
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_version_name()
        """
        try:
            p = self._parse_manifest_xml()['versionName']
            self._manifest_analysis['version_name'] = [p]
            self.log_debug('')
            return [p]
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_main_activity(self) -> dict:
        """
        Returns the main launchable activity as a dict

        :return: Main activity and its attributes
        :rtype: dict
        """

        activities = self.manifest_activities()
        for i in range(len(activities)):
            try:
                if activities[i]['intent-filter']['action']['name'] == 'android.intent.action.MAIN':
                    return activities[i]
            except:
                continue

    @_logger
    def manifest_version_code(self) -> list:
        """
        Returns the version code from the APK
        | `Reference <https://developer.android.com/guide/topics/manifest/manifest-element>`__

        :return: version code
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_version_code()
        """
        try:
            p = self._parse_manifest_xml()['versionCode']
            self._manifest_analysis['version_code'] = [p]
            self.log_debug('')
            return [p]
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_platform_build_version_name(self) -> list:
        """
        Returns the platform build version name from the APK

        :return: platform build version name
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_platform_build_version_name()
        """
        try:
            p = self._parse_manifest_xml()['platformBuildVersionCode']
            self._manifest_analysis['platform_build_version_name'] = [p]
            self.log_debug('')
            return [p]
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_platform_build_version_code(self) -> list:
        """
        Returns the platform build version code from the APK

        :return: platform build version code
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_platform_build_version_code()
        """
        try:
            p = self._parse_manifest_xml()['platformBuildVersionCode']
            self._manifest_analysis['platform_build_version_code'] = [p]
            self.log_debug('')
            return [p]
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_target_sdk(self) -> list:
        """
        Returns the target SDK from the APK
        | `Reference <https://developer.android.com/guide/topics/manifest/uses-sdk-element>`__

        :return: target SDK
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_target_sdk()
        """
        try:
            p = self._parse_manifest_xml()['uses-sdk']['targetSdkVersion']
            self._manifest_analysis['target_sdk'] = [p]
            self.log_debug('')
            return [p]
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_min_sdk(self) -> list:
        """
        Returns the minimum SDK from the APK
        | `Reference <https://developer.android.com/guide/topics/manifest/uses-sdk-element>`__

        :return: minimum SDK
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_min_sdk()
        """
        try:
            p = self._parse_manifest_xml()[
                'uses-sdk']['minSdkVersion']
            self._manifest_analysis['min_sdk'] = [p]
            self.log_debug('')
            return [p]
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_android_version(self) -> list:
        """
        Returns the version number matching for min and target sdk.

        :return: Android versions based on min and target sdk
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_android_version()
        """
        min_sdk = [x for x in _AppAnalysisConstants._ANDROID_VERSIONS
                   if x['api'] == str(self.manifest_min_sdk()[0])][0]
        target_sdk = [x for x in _AppAnalysisConstants._ANDROID_VERSIONS
                      if x['api'] == str(self.manifest_target_sdk()[0])][0]
        match = {'min_sdk': min_sdk, 'target_sdk': target_sdk}
        self._manifest_analysis['android_version'] = match
        self.log_debug('')
        return match

    @_logger
    def manifest_uses_configuration(self) -> dict:
        """
        Returns the uses-configuration and all attributes from the APK
        | `Reference <https://developer.android.com/guide/topics/manifest/uses-configuration-element>`__

        :return: uses configuration
        :rtype: dict

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.uses_configuration()
        """
        try:
            p = self._parse_manifest_xml()['uses-configuration']
            self._manifest_analysis['uses_configuration'] = p
            self.log_debug('')
            return p
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_uses_library(self) -> dict:
        """
        Returns the uses-library and all attributes from the APK
        | `Reference <https://developer.android.com/guide/topics/manifest/uses-library-element>`__

        :return: uses library
        :rtype: dict

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_uses_library()
        """
        try:
            p = self._parse_manifest_xml()[
                'application']['uses-library']
            self._manifest_analysis['uses_library'] = [p]
            self.log_debug('')
            return p
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_uses_permission(self, merged: bool=True) -> list:
        """
        Returns a list of application permission and their attributes. This 
        is the main way stating permissions in AndroidManifest.xml file 
        | `Reference <https://developer.android.com/guide/topics/manifest/uses-permission-element>`__

        :param bool merged: Merge the two permisison types into one list
        :return: Permissions and their attributes
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_uses_permissions()
        """
        try:
            a = self._parse_manifest_xml()['uses-permission']
            self._manifest_analysis['uses-permission'] = a
            self.log_debug('')
            return a
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_permission(self, merged: bool=True) -> list:
        """
        Returns a list of application permission and their attributes
        | `Reference <https://developer.android.com/guide/topics/manifest/permission-element>`__

        :param bool merged: Merge the two permisison types into one list
        :return: Permissions and their attributes
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_permission()
        """
        try:
            a = self._parse_manifest_xml()['permission']
            self._manifest_analysis['permission'] = a
            self.log_debug('')
            return a
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_bind_permissions(self):
        """
        Returns a list of permissions that have the BIND property. This 
        allows this permission scope to be executed with the scope of the system

        :return: List of BIND permissions
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_bind_permissions()
        """
        try:
            permissions = [x['name'] for x in self.manifest_uses_permission()]
            return list(filter(lambda x: 'BIND' in x, permissions))
        except:
            self.log_error('Exception happened')

    @_logger
    def manifest_custom_permission(self) -> dict:
        """
        Parses the manifest for permissions and returns a dict of only 
        custom permissions.
        | `Referene <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#testing-app-permissions>`__

        :return: Custom permissions
        :rtype: dict

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_custom_permission()
        """
        final = []
        p1 = self.manifest_uses_permission()
        if p1 is None:
            p1 = []
        up = self.manifest_permission()
        if up is not None:
            p1 += up
        for i in range(len(p1)):
            try:
                if not p1[i]['name'].startswith('android.permission'):
                    final.append(p1[i]['name'])
            except KeyError:
                self.log_error('Key not found')
            except TypeError:
                self.log_error('Key not found')
        self._manifest_analysis['custom_permission'] = final
        self.log_debug('')
        return final

    @_logger
    def manifest_signature_permission(self) -> dict:
        """
        Parses the manifest for permissions and returns a dict of only 
        signature permissions
        | `Reference Android SDK <https://developer.android.com/guide/topics/permissions/overview#signature_permissions>`__
        | `Referene <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#testing-app-permissions>`__

        :return: Signature permissions
        :rtype: dict

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_signature_permission()
        """
        final = []
        p1 = self.manifest_uses_permission()
        if p1 is None:
            p1 = []
        up = self.manifest_permission()
        if up is not None:
            p1 += up
        for i in range(len(p1)):
            try:
                p = p1[i]['name']
                if any(sig in p for sig in self._PERMISSION_SIGNATURE):
                    final.append(p)
            except KeyError:
                self.log_error('Key not found')
                continue
            except TypeError:
                self.log_error('Key not found')
                continue
        self._manifest_analysis['signature_permission'] = final
        self.log_debug('')
        return final

    @_logger
    def manifest_dangerous_permission(self):
        """
        Parses the manifest for permissions and returns a dict of only 
        dangerous permissions
        | `Reference Android SDK <https://developer.android.com/guide/topics/permissions/overview#dangerous_permissions>`__
        | `Referene <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#testing-app-permissions>`__

        :return: Dangerous permissions
        :rtype: dict

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_dangerous_permission()
        """
        final = []
        p1 = self.manifest_uses_permission()
        if p1 is None:
            p1 = []
        up = self.manifest_permission()
        if up is not None:
            p1 += up
        for i in range(len(p1)):
            try:
                p = p1[i]['name']
                if any(sig in p for sig in self._PERMISSION_DANGERIOUS):
                    final.append(p)
            except KeyError:
                self.log_error('Key not found')
                continue
            except TypeError:
                self.log_error('Key not found')
                continue
        self._manifest_analysis['dangerous_permission'] = final
        self.log_debug('')
        return final

    @_logger
    def manifest_intent_uri_filter(self):
        """
        Parses the manifest for permissions and returns a dict of only 
        dangerous permissions
        | `Referene <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#static-analysis-1>`__

        :return: Intent filter uri's
        :rtype: dict

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_intent_uri_filter()
        """
        try:
            final = []
            activities = self.manifest_activities()
            for i in range(len(activities)):
                a = activities[i]
                try:
                    if 'intent-filter' in a:
                        a['intent-filter']
                        final.append(a)
                except KeyError:
                    continue
            self._manifest_analysis['intent_filter_uri'] = final
            self.log_debug('')
            return final
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_uses_feature(self):
        """
        Returns a list of all uses-feature node. uses-feature is normally used 
        to elaborate on permissions. 
        | `Reference <https://developer.android.com/guide/topics/manifest/uses-feature-element>`__

        :return: Attributes of found uses-feature nodes
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_uses_feature()
        """
        try:
            a = permission = self._parse_manifest_xml()['uses-feature']
            self._manifest_analysis['uses_feature'] = a
            self.log_debug('')
            return a
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_allow_backup(self):
        """
        Returns true if the allow backup flag is set for the APK
        | `Reference <https://developer.android.com/guide/topics/manifest/application-element>`__

        :return: true or false
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_allow_backup()
        """
        try:
            p = self.manifest_application_node()['allowBackup']
            self._manifest_analysis['allow_backup'] = [p]
            self.log_debug('')
            return [p]
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_debuggable(self):
        """
        Returns true if the debuggable flag is set for the APK
        | `Reference <https://developer.android.com/guide/topics/manifest/application-element>`__
        | `Reference <https://wiki.sei.cmu.edu/confluence/display/android/DRD10-X.+Do+not+release+apps+that+are+debuggable>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#determining-whether-the-app-is-debuggable>`__

        :return: true or false
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_debuggable()
        """
        try:
            p = self.manifest_application_node()['debuggable']
            self._manifest_analysis['debuggable'] = [p]
            self.log_debug('')
            return [p]
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_application_node(self) -> dict:
        """
        Returns a dictionary of all values that are found in the application node
        | `Reference <https://developer.android.com/guide/topics/manifest/application-element>`__

        :return: dictionary of matches
        :rtype: dict

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_application_node()
        """
        try:
            p = self._parse_manifest_xml()['application']
            self._manifest_analysis['application_node'] = p
            self.log_debug('')
            return p
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_meta_data(self):
        """
        Returns the contents inside meta-data nodes
        | `Reference <https://developer.android.com/guide/topics/manifest/meta-data-element>`__

        :return: meta-data
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_meta_data()
        """
        try:
            a = []
            if 'meta-data' in self._parse_manifest_xml():
                a.append(self._parse_manifest_xml()['meta-data'])
            if 'meta-data' in self.manifest_application_node():
                a += self.manifest_application_node()['meta-data']
            self._manifest_analysis['meta_data'] = a
            self.log_debug('')
            return a
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_activities(self):
        """
        Returns a list of all activities and all related attributes
        | `Reference <https://developer.android.com/guide/topics/manifest/activity-element>`__
        | `Reference <https://developer.android.com/guide/topics/manifest/intent-filter-element>`__

        :return: activities
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_activities()
        """
        a = self._parse_manifest_xml()['application']['activity']
        self._manifest_analysis['activities'] = a
        self.log_debug('')
        return a

    @_logger
    def manifest_activity_alias(self):
        """
        Returns a list of all activity-alias and all related attributes
        | `Reference <https://developer.android.com/guide/topics/manifest/activity-alias-element>`__

        :return: activitiy aliases
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_activity_alias()
        """
        try:
            a = self.manifest_application_node()['activity-alias']
            self._manifest_analysis['activity_alias'] = a
            self.log_debug('')
            return a
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_receivers(self):
        """
        Returns a list of all receivers and all related attributes
        | `Reference <https://developer.android.com/guide/topics/manifest/receiver-element>`__

        :return: receivers
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_receivers()
        """
        try:
            a = self.manifest_application_node()['receiver']
            self._manifest_analysis['receiver'] = a
            self.log_debug('')
            return a
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_services(self):
        """
        Returns a list of all services and all related attributes
        | `Reference <https://developer.android.com/guide/topics/manifest/service-element>`__

        :return: services
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_services()
        """
        try:
            a = self.manifest_application_node()['service']
            self._manifest_analysis['services'] = a
            self.log_debug('')
            return a
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_providers(self):
        """
        Returns a list of all providers and all related attributes
        | `Reference <https://developer.android.com/guide/topics/manifest/provider-element>`__
        | `Reference <https://developer.android.com/guide/topics/manifest/path-permission-element>`__

        :return: providers
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_providers()
        """
        try:
            if self.manifest_application_node()['provider']:
                a = self.manifest_application_node()
                self._manifest_analysis['providers'] = a
                self.log_debug('')
                return a
        except KeyError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_exported_providers(self):
        """
        Returns a list of all providers and all related attributes
        | `Reference <https://developer.android.com/guide/topics/manifest/provider-element>`__
        | `Reference OWASP <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#inspect-the-android-manifest>`__

        :return: providers which are exported
        :rtype: list

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.manifest_exported_providers()
        """
        try:
            return [x for x in self.manifest_providers() if x['exported'] == 'true']
        except KeyError:
            self.log_error('Key not found')
            return []
        except TypeError:
            self.log_error('Key not found')
            return []

    @_logger
    def manifest_secrets(self):
        """
        Find all secrets hidden in AndroidManifest.xml like tokens, keys etc.

        :return: name, line number and match
        :rtype: dict

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAnroid('/path/to/apk')
        >>> a.manifest_secrets()
        """
        g = self._run_rg(regex=self._RG_MANIFEST_SECRET, code=True, rg_options='-iH',
                         path=f'{self._manifest_path}')
        match = self._process_match(g, is_url=True)
        self._manifest_analysis['secrets'] = match
        self.log_debug('')
        return match
