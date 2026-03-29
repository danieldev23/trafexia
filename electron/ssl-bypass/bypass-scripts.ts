/**
 * Frida JS bypass scripts as string templates.
 * Each function returns a self-contained Frida script that bypasses
 * SSL pinning for a specific framework.
 *
 * Key design: scripts are plain strings (not TS code) because they
 * run inside the Frida JS runtime on the target device.
 */

export function bypassRootAndEmulator(): string {
  return `
(function() {
  try {
    var File = Java.use("java.io.File");
    var Runtime = Java.use("java.lang.Runtime");
    var SystemProperties = Java.use("android.os.SystemProperties");

    var rootPaths = [
      "/system/app/Superuser.apk",
      "/sbin/su",
      "/system/bin/su",
      "/system/xbin/su",
      "/data/local/xbin/su",
      "/data/local/bin/su",
      "/system/sd/xbin/su",
      "/system/bin/failsafe/su",
      "/data/local/su",
      "/su/bin/su",
      "/data/local/tmp/frida-server",
      "/data/local/tmp/frida",
      "magisk",
      "frida",
      "xposed"
    ];

    var emuProps = {
      "ro.kernel.qemu": "0",
      "ro.hardware": "shamu",
      "ro.product.model": "Pixel 6",
      "ro.product.manufacturer": "Google",
      "ro.product.name": "shamu",
      "ro.product.device": "shamu",
      "ro.product.board": "shamu",
      "ro.build.tags": "release-keys",
      "ro.build.type": "user",
      "ro.debuggable": "0",
      "ro.secure": "1"
    };

    // Hook File.exists / File.canRead
    File.exists.implementation = function() {
      var name = this.getAbsolutePath();
      for (var i = 0; i < rootPaths.length; i++) {
        if (name.indexOf(rootPaths[i]) !== -1) {
          console.log("[+] Hiding root file/folder: " + name);
          return false;
        }
      }
      return this.exists();
    };
    File.canRead.implementation = function() {
      var name = this.getAbsolutePath();
      for (var i = 0; i < rootPaths.length; i++) {
        if (name.indexOf(rootPaths[i]) !== -1) {
          return false;
        }
      }
      return this.canRead();
    };

    // Hook Runtime.exec
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
      if (cmd.indexOf("su") !== -1 || cmd.indexOf("magisk") !== -1) {
        console.log("[+] Intercepted root command execution: " + cmd);
        var err = Java.use("java.io.IOException").$new("Cannot run program \\"su\\": error=2, No such file or directory");
        throw err;
      }
      return this.exec(cmd);
    };
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
      if (cmdArray && cmdArray.length > 0 && (cmdArray[0] === "su" || cmdArray[0] === "magisk")) {
         console.log("[+] Intercepted root command execution: " + cmdArray[0]);
         var err = Java.use("java.io.IOException").$new("Cannot run program \\"su\\": error=2, No such file or directory");
         throw err;
      }
      return this.exec(cmdArray);
    };
    
    // Hook SystemProperties to hide emulator
    SystemProperties.get.overload('java.lang.String').implementation = function(key) {
      if (emuProps[key] !== undefined) {
        console.log("[+] Faking prop " + key + " -> " + emuProps[key]);
        return emuProps[key];
      }
      var res = this.get(key);
      // Generic mask for emulator string
      if (res && typeof res === 'string' && (res.indexOf('qemu') !== -1 || res.indexOf('goldfish') !== -1 || res.indexOf('vbox') !== -1)) {
        return "android";
      }
      return res;
    };
    SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
      if (emuProps[key] !== undefined) {
        return emuProps[key];
      }
      return this.get(key, def);
    };

    // Hook Packages check
    try {
      var PackageManager = Java.use("android.app.ApplicationPackageManager");
      PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkgName, flags) {
        var suspiciousPkgs = ["com.topjohnwu.magisk", "eu.chainfire.supersu", "com.noshufou.android.su", "com.joeykrim.rootcheck"];
        if (suspiciousPkgs.indexOf(pkgName) !== -1) {
          console.log("[+] Hiding package: " + pkgName);
          var err = Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkgName);
          throw err;
        }
        return this.getPackageInfo(pkgName, flags);
      };
    } catch (e) { }

    console.log('[+] Root & Emulator Evasion Active');
  } catch (e) {
    console.log('[-] Root/Emulator hook failed: ' + e.message);
  }
})();
`;
}

export function bypassOkHttp3(): string {
  return `
(function() {
  try {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
      console.log('[+] OkHttp3 CertificatePinner.check bypassed for: ' + hostname);
    };
    CertificatePinner.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function(hostname, cleanedCertificates) {
      console.log('[+] OkHttp3 CertificatePinner.check$okhttp bypassed for: ' + hostname);
    };
  } catch (e1) {
    try {
      var CertificatePinner2 = Java.use('okhttp3.CertificatePinner');
      CertificatePinner2.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
        console.log('[+] OkHttp3 CertificatePinner.check (fallback) bypassed for: ' + hostname);
      };
    } catch (e2) {
      console.log('[-] OkHttp3 CertificatePinner not found: ' + e2.message);
    }
  }

  // Bypass OkHttp3 TrustManager
  try {
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var X509Certificate = Java.use('java.security.cert.X509Certificate');

    var TrustManagerImpl = Java.registerClass({
      name: 'com.trafexia.TrustManager',
      implements: [TrustManager],
      methods: {
        checkClientTrusted: function(chain, authType) { },
        checkServerTrusted: function(chain, authType) { },
        getAcceptedIssuers: function() { return []; }
      }
    });

    var TrustManagers = [TrustManagerImpl.$new()];
    var sslContext = SSLContext.getInstance('TLS');
    sslContext.init(null, TrustManagers, null);
    SSLContext.getInstance.overload('java.lang.String').implementation = function(protocol) {
      var ctx = this.getInstance(protocol);
      ctx.init(null, TrustManagers, null);
      console.log('[+] OkHttp3 SSLContext.getInstance bypassed for: ' + protocol);
      return ctx;
    };
  } catch (e3) {
    console.log('[-] OkHttp3 SSLContext bypass failed: ' + e3.message);
  }
})();
`;
}

export function bypassConscrypt(): string {
  return `
(function() {
  try {
    var Platform = Java.use('com.android.org.conscrypt.Platform');
    Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.AbstractConscryptSocket').implementation = function(tm, chain, authType, socket) {
      console.log('[+] Conscrypt Platform.checkServerTrusted bypassed');
    };
  } catch (e1) {
    console.log('[-] Conscrypt Platform.checkServerTrusted not found: ' + e1.message);
  }

  try {
    var ConscryptEngineSocket = Java.use('com.android.org.conscrypt.ConscryptEngineSocket');
    ConscryptEngineSocket.verifyCertificateChain.implementation = function(certRefs, authMethod) {
      console.log('[+] Conscrypt ConscryptEngineSocket.verifyCertificateChain bypassed');
    };
  } catch (e2) {
    console.log('[-] Conscrypt ConscryptEngineSocket not found: ' + e2.message);
  }

  try {
    var ConscryptFileDescriptorSocket = Java.use('com.android.org.conscrypt.ConscryptFileDescriptorSocket');
    ConscryptFileDescriptorSocket.verifyCertificateChain.implementation = function(certRefs, authMethod) {
      console.log('[+] Conscrypt ConscryptFileDescriptorSocket.verifyCertificateChain bypassed');
    };
  } catch (e3) {
    console.log('[-] Conscrypt ConscryptFileDescriptorSocket not found: ' + e3.message);
  }

  // Android default TrustManager
  try {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
      console.log('[+] Conscrypt TrustManagerImpl.verifyChain bypassed for: ' + host);
      return untrustedChain;
    };
  } catch (e4) {
    console.log('[-] Conscrypt TrustManagerImpl not found: ' + e4.message);
  }
})();
`;
}

export function bypassWebView(): string {
  return `
(function() {
  try {
    var WebViewClient = Java.use('android.webkit.WebViewClient');
    WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
      console.log('[+] WebView SSL error bypassed, proceeding...');
      handler.proceed();
    };
  } catch (e1) {
    console.log('[-] WebViewClient.onReceivedSslError not found: ' + e1.message);
  }

  // Also hook SslErrorHandler
  try {
    var SslErrorHandler = Java.use('android.webkit.SslErrorHandler');
    SslErrorHandler.proceed.implementation = function() {
      console.log('[+] WebView SslErrorHandler.proceed called');
      this.proceed();
    };
  } catch (e2) {
    console.log('[-] WebView SslErrorHandler not accessible: ' + e2.message);
  }
})();
`;
}

export function bypassFlutter(): string {
  return `
(function() {
  // Flutter uses BoringSSL internally via libflutter.so
  // We need to find and patch ssl_crypto_x509_session_verify_cert_chain
  try {
    var libflutter = Process.findModuleByName('libflutter.so');
    if (!libflutter) {
      console.log('[-] libflutter.so not found, trying to wait...');
      // Try to hook dlopen to catch late-loaded libflutter
      var dlopen = Module.findExportByName(null, 'dlopen');
      if (dlopen) {
        Interceptor.attach(dlopen, {
          onEnter: function(args) {
            this.path = args[0].readCString();
          },
          onLeave: function(retval) {
            if (this.path && this.path.indexOf('libflutter.so') !== -1) {
              console.log('[+] libflutter.so loaded, patching...');
              patchFlutterSsl();
            }
          }
        });
      }
      return;
    }
    patchFlutterSsl();
  } catch (e) {
    console.log('[-] Flutter bypass error: ' + e.message);
  }

  function patchFlutterSsl() {
    var libflutter = Process.findModuleByName('libflutter.so');
    if (!libflutter) return;

    // Pattern for ssl_crypto_x509_session_verify_cert_chain
    // This searches for the function signature in the binary
    var patterns = [
      // Android ARM64 pattern for "x509_session_verify_cert_chain" error string ref
      'FF 03 01 D1 FD 7B 03 A9 FD C3 00 91',
      // Alternative pattern
      'F8 5F BC A9 F6 57 01 A9 F4 4F 02 A9 FD 7B 03 A9',
    ];

    var found = false;
    for (var i = 0; i < patterns.length; i++) {
      Memory.scan(libflutter.base, libflutter.size, patterns[i], {
        onMatch: function(address, size) {
          console.log('[+] Flutter SSL verify function found at: ' + address);
          Interceptor.replace(address, new NativeCallback(function(pathPtr, leafPtr, chainPtr) {
            console.log('[+] Flutter ssl_crypto_x509_session_verify_cert_chain bypassed');
            return 1; // Return success
          }, 'int', ['pointer', 'pointer', 'pointer']));
          found = true;
        },
        onComplete: function() {
          if (!found) {
            console.log('[-] Flutter SSL verify pattern ' + i + ' not found');
          }
        }
      });
      if (found) break;
    }

    // Alternative: hook ssl_verify_peer_cert
    if (!found) {
      try {
        var ssl_verify = Module.findExportByName('libflutter.so', 'ssl_verify_peer_cert');
        if (ssl_verify) {
          Interceptor.replace(ssl_verify, new NativeCallback(function() {
            console.log('[+] Flutter ssl_verify_peer_cert bypassed');
            return 0;
          }, 'int', []));
          found = true;
        }
      } catch (e) {
        console.log('[-] Flutter ssl_verify_peer_cert hook failed: ' + e.message);
      }
    }
  }
})();
`;
}

export function bypassReactNative(): string {
  return `
(function() {
  // React Native typically uses OkHttp under the hood
  try {
    var OkHostnameVerifier = Java.use('com.android.okhttp.internal.tls.OkHostnameVerifier');
    OkHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(hostname, session) {
      console.log('[+] React Native OkHostnameVerifier.verify bypassed for: ' + hostname);
      return true;
    };
    OkHostnameVerifier.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(hostname, certificate) {
      console.log('[+] React Native OkHostnameVerifier.verify (cert) bypassed for: ' + hostname);
      return true;
    };
  } catch (e1) {
    console.log('[-] React Native OkHostnameVerifier not found: ' + e1.message);
  }

  // React Native networking module
  try {
    var NetworkingModule = Java.use('com.facebook.react.modules.network.NetworkingModule');
    // Hook the custom client builder if present
    console.log('[+] React Native NetworkingModule found');
  } catch (e2) {
    console.log('[-] React Native NetworkingModule not found: ' + e2.message);
  }

  // Hook HostnameVerifier interface implementations
  try {
    var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
    var allClasses = Java.enumerateLoadedClassesSync();
    for (var i = 0; i < allClasses.length; i++) {
      try {
        var cls = Java.use(allClasses[i]);
        if (cls.class.getInterfaces().toString().indexOf('HostnameVerifier') !== -1) {
          cls.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(hostname, session) {
            console.log('[+] HostnameVerifier bypassed for: ' + hostname + ' (' + this.getClass().getName() + ')');
            return true;
          };
        }
      } catch (e) {
        // Skip classes that don't match
      }
    }
  } catch (e3) {
    console.log('[-] HostnameVerifier enumeration failed: ' + e3.message);
  }
})();
`;
}

export function universalBypass(): string {
  return `
Java.perform(function() {
  console.log('[*] Trafexia Universal SSL Pinning Bypass starting...');

  // === Root / Emulator Evasion ===
  try {
    ${bypassRootAndEmulator().trim()}
  } catch (e) {
    console.log('[-] Root/Emulator bypass error: ' + e.message);
  }

  // === OkHttp3 ===
  try {
    ${bypassOkHttp3().trim()}
  } catch (e) {
    console.log('[-] OkHttp3 bypass module error: ' + e.message);
  }

  // === Conscrypt / Android default ===
  try {
    ${bypassConscrypt().trim()}
  } catch (e) {
    console.log('[-] Conscrypt bypass module error: ' + e.message);
  }

  // === WebView ===
  try {
    ${bypassWebView().trim()}
  } catch (e) {
    console.log('[-] WebView bypass module error: ' + e.message);
  }

  // === React Native ===
  try {
    ${bypassReactNative().trim()}
  } catch (e) {
    console.log('[-] React Native bypass module error: ' + e.message);
  }

  // === Generic javax.net.ssl / HttpsURLConnection ===
  try {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustManager = Java.registerClass({
      name: 'com.trafexia.UniversalTrustManager',
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function(chain, authType) { },
        checkServerTrusted: function(chain, authType) { },
        getAcceptedIssuers: function() { return []; }
      }
    });

    var TrustManagers = [TrustManager.$new()];
    var SSLContextInit = SSLContext.init;

    // Hook HttpsURLConnection
    try {
      var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
      HttpsURLConnection.setDefaultSSLSocketFactory.implementation = function(factory) {
        console.log('[+] HttpsURLConnection.setDefaultSSLSocketFactory intercepted');
        var ctx = SSLContext.getInstance('TLS');
        ctx.init(null, TrustManagers, null);
        this.setDefaultSSLSocketFactory(ctx.getSocketFactory());
      };
      HttpsURLConnection.setSSLSocketFactory.implementation = function(factory) {
        console.log('[+] HttpsURLConnection.setSSLSocketFactory intercepted');
        var ctx = SSLContext.getInstance('TLS');
        ctx.init(null, TrustManagers, null);
        this.setSSLSocketFactory(ctx.getSocketFactory());
      };
      HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
        console.log('[+] HttpsURLConnection.setDefaultHostnameVerifier intercepted');
        // Don't set any real verifier
      };
    } catch (e) {
      console.log('[-] HttpsURLConnection hooks failed: ' + e.message);
    }

    console.log('[+] Generic TrustManager bypass applied');
  } catch (e) {
    console.log('[-] Generic TrustManager bypass failed: ' + e.message);
  }

  console.log('[+] Trafexia Universal SSL Pinning Bypass loaded');
});

// === Flutter (native layer, outside Java.perform) ===
try {
  ${bypassFlutter().trim()}
} catch (e) {
  console.log('[-] Flutter bypass module error: ' + e.message);
}
`;
}

/**
 * Get the bypass script for a specific framework.
 */
export function getBypassScript(framework: string): string {
  // Always include root/emulator evasion alongside specific frameworks
  const evasion = bypassRootAndEmulator();

  switch (framework) {
    case "okhttp3":
      return wrapJavaPerform(evasion + "\\n" + bypassOkHttp3());
    case "conscrypt":
      return wrapJavaPerform(evasion + "\\n" + bypassConscrypt());
    case "webview":
      return wrapJavaPerform(evasion + "\\n" + bypassWebView());
    case "flutter":
      return wrapJavaPerform(evasion) + "\\n" + bypassFlutter();
    case "react-native":
      return wrapJavaPerform(evasion + "\\n" + bypassReactNative());
    case "all":
    case "auto":
    default:
      return universalBypass();
  }
}

function wrapJavaPerform(script: string): string {
  return `Java.perform(function() {\n${script}\n});`;
}
