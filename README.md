<img src="https://github.com/securisec/glorifiedgrep/blob/master/logo.png" width="150px">


[![Build Status](https://travis-ci.com/securisec/glorifiedgrep.svg?token=8GQfGnTK7S1NU7bKCqeR&branch=master)](https://travis-ci.com/securisec/glorifiedgrep)
[![Read the Docs](https://img.shields.io/readthedocs/glorifiedgrep.svg)](https://glorifiedgrep.readthedocs.io/en/latest/)

# [DOCS](https://glorifiedgrep.readthedocs.io/en/latest/)

# Glorified Grep

`glorifiedgrep` is exactly what it sounds like... glorified grep. 

What motivated this project is seeing lots of tools for static analysis of applications specially Android applications. But most of these applications are all pretty much doing the same thing.

The aim of `glorifiedgrep` is to have a python module that allows the creation of such tools without the extra heavy lifting required. Underneath, `glorifiedgrep` uses [ripgrep](https://github.com/BurntSushi/ripgrep) to search for predefined patterns. 

Best effort has been given to document and reference all the methods. Refer to the docs for further documentation.

What can `glorifiedgrep` be used for? 
- Analyze applications pythonically
- Build tools for application analysis without the overhead of writing all of your own code.

If you are not sure what a method is called, glorified grep offers a helper method to search for them. 
```
from glorifiedgrep import GlorifiedAndroid
g = GlorifiedAndroid('/path/to/apk')
print(g.search_methods('webview'))

['code_webview_content_access', 'code_webview_database', 'code_webview_debug_enabled', 'code_webview_file_access', 'code_webview_get_request', 'code_webview_js_enabled', 'code_webview_post_request', 'owasp_webview_cert_pinning', 'owasp_webview_loadurl', 'owasp_webview_native_function', 'owasp_webview_ssl_ignore']
```

## Hard requirements
`glorifiedgrep` has one hard dependency. ripgrep. It will attempt to load `rg` from path, but this can be overwritten using `rg_path` paramter in the class. Refer to the docs for more info. 

## Install
### Pypi
**Developed using python 3.7**
It is recommended that you use virtualenv to install as some dependencies might break your other libs.
```
pip3 install glorifiedgrep
```
### Dev build
```
git clone https://github.com/securisec/glorifiedgrep.git
cd glorifiedgrep
pip install .
```
#### OSX
`libmagic` is required. Easiest way to install it is `brew install libmagic`

## Coverage
### Android
Currently, `glorifiedgrep` supports Android APK analysis OOB. It takes an apk file path, decompiles it using jadx, and then performs various analysis depending on the methods called.

The **GlorifiedAndroid** class does support flexiblity.
- If you dont want to use the built in req of jadx, and want to use your pwn decompiler, then you can use
    ```
    from glorifiedgrep.android import CodeAnalysis
    ```
    This class takes *source_path* as a paramter. The source_path should include all of you decompiled java codes.
- It also supports the concept of projects. By default, **GlorifiedAndroid** class will will setup all the output into `/tmp/GlorifiedAndroid/` directory. This can be overwritten using the `output_dir` parameter. In the future, if the `apk_path` and `output_dir` parameters are both specified, then it will not try to decompile again.
#### Android sub modules
`glorifiedgrep` offers the following Android sub modules that can be used independantly of the main **GlorifiedAndroid** class. Invoke as `from glorifiedgrep.android import ClassName`
- **CertAnalysis**: Perform analysis on an Android RSA signing cert. Takes the path to the cert as an argument.
- **CodeAnalysis**: Perform code analysis on a directory that contains the decompiled java classes. Takes the path to the source directory as an argument.
- **ManifestAnalysis**: Perform analysis on the Android application manifest file. Takes path to the manifest file as an argument.
- **OtherAnalysis**: Perform other source code related analysis.
- **OWASPAnalysis**: Perform source code analysis based on OWASP MASVS. 
- There are a few other modules that are available which includes *malware*, *utils* and *react*. Refer to the docs for more information. 

#### Usage
```
from glorifiedgrep import GlorifiedAndroid
glory = GlorifiedAndroid('/path/to/apk')
```

### dotNet
Not implemented yet

### JS
Not implemented yet

## Tested on
- Ubuntu
- OSX
- Does not work properly on **Windows**

# Pull requests
All pull requests must accompany test cases. If not, they will be rejected. 