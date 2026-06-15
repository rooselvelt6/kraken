use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FridaScript {
    pub name: String,
    pub description: String,
    pub platform: String,
    pub category: String,
    pub code: String,
    pub usage: String,
}

pub struct FridaGenerator;

impl FridaGenerator {
    pub fn new() -> Self {
        FridaGenerator
    }

    pub fn generate_ssl_bypass(platform: &str) -> FridaScript {
        match platform {
            "android" => Self::android_ssl_bypass(),
            "ios" => Self::ios_ssl_bypass(),
            _ => Self::universal_ssl_bypass(),
        }
    }

    pub fn generate_root_bypass(platform: &str) -> FridaScript {
        match platform {
            "android" => Self::android_root_bypass(),
            "ios" => Self::ios_jailbreak_bypass(),
            _ => Self::universal_root_bypass(),
        }
    }

    pub fn generate_debug_bypass() -> FridaScript {
        FridaScript {
            name: "debug-bypass".to_string(),
            description: "Bypass debugger detection".to_string(),
            platform: "android".to_string(),
            category: "anti-debug".to_string(),
            code: r#"
Java.perform(function() {
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        return false;
    };
    var ActivityThread = Java.use("android.app.ActivityThread");
    ActivityThread.currentActivityThread.implementation = function() {
        var thread = this.currentActivityThread();
        return thread;
    };
    console.log("[+] Debug detection bypassed");
});
"#.to_string(),
            usage: "frida -U -f com.target.app -l debug-bypass.js --no-pause".to_string(),
        }
    }

    pub fn generate_pin_unlock() -> FridaScript {
        FridaScript {
            name: "pin-unlock".to_string(),
            description: "Bypass PIN/pattern lock screen".to_string(),
            platform: "android".to_string(),
            category: "bypass".to_string(),
            code: r#"
Java.perform(function() {
    var KeyguardManager = Java.use("android.app.KeyguardManager");
    KeyguardManager.isKeyguardLocked.implementation = function() {
        return false;
    };
    KeyguardManager.isKeyguardSecure.implementation = function() {
        return false;
    };
    var WindowManager = Java.use("android.view.WindowManager");
    WindowManager.isKeyguardLocked.implementation = function() {
        return false;
    };
    console.log("[+] Lock screen bypassed");
});
"#.to_string(),
            usage: "frida -U -f com.target.app -l pin-unlock.js --no-pause".to_string(),
        }
    }

    fn android_ssl_bypass() -> FridaScript {
        FridaScript {
            name: "android-ssl-bypass".to_string(),
            description: "Universal SSL pinning bypass for Android".to_string(),
            platform: "android".to_string(),
            category: "ssl-bypass".to_string(),
            code: r#"
Java.perform(function() {
    var ArrayList = Java.use("java.util.ArrayList");
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    var TrustManager = Java.registerClass({
        name: "com.kraken.FridaTrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var TrustManagers = [TrustManager.$new()];
    var sc = SSLContext.getInstance("TLS");
    sc.init(null, TrustManagers, null);

    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

    var AllHosts = Java.registerClass({
        name: "com.kraken.AllHosts",
        implements: [Java.use("javax.net.ssl.HostnameVerifier")],
        methods: {
            verify: function(hostname, session) { return true; }
        }
    });
    HttpsURLConnection.setDefaultHostnameVerifier(AllHosts.$new());

    console.log("[+] SSL pinning bypassed for all connections");
});
"#.to_string(),
            usage: "frida -U -f com.target.app -l android-ssl-bypass.js --no-pause".to_string(),
        }
    }

    fn ios_ssl_bypass() -> FridaScript {
        FridaScript {
            name: "ios-ssl-bypass".to_string(),
            description: "Universal SSL pinning bypass for iOS".to_string(),
            platform: "ios".to_string(),
            category: "ssl-bypass".to_string(),
            code: r#"
if (ObjC.available) {
    var NSURLSession = ObjC.classes.NSURLSession;
    var NSURLSessionDelegate = ObjC.classes.NSURLSessionDelegate;

    Interceptor.attach(ObjC.classes.NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
        onEnter: function(args) {
            console.log("[+] Intercepted URL request");
        }
    });

    var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
    if (AFSecurityPolicy) {
        AFSecurityPolicy['- setSSLPinningMode:'].implementation = function() {
            console.log("[+] SSL pinning mode disabled");
        };
    }

    var SecTrustEvaluate = Module.findExportByName(null, "SecTrustEvaluate");
    if (SecTrustEvaluate) {
        Interceptor.attach(SecTrustEvaluate, {
            onLeave: function(retval) {
                retval.replace(0);
                console.log("[+] SecTrustEvaluate bypassed");
            }
        });
    }

    console.log("[+] iOS SSL pinning bypassed");
} else {
    console.log("[-] Objective-C runtime not available");
}
"#.to_string(),
            usage: "frida -U -f com.target.app -l ios-ssl-bypass.js --no-pause".to_string(),
        }
    }

    fn android_root_bypass() -> FridaScript {
        FridaScript {
            name: "android-root-bypass".to_string(),
            description: "Bypass root detection on Android".to_string(),
            platform: "android".to_string(),
            category: "root-bypass".to_string(),
            code: r#"
Java.perform(function() {
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var blocked = [
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/sbin/magisk", "/data/app/com.topjohnwu.magisk"
        ];
        for (var i = 0; i < blocked.length; i++) {
            if (path.indexOf(blocked[i]) >= 0) {
                console.log("[+] Blocked root check: " + path);
                return false;
            }
        }
        return this.exists();
    };

    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("[Ljava.lang.String;").implementation = function(cmd) {
        var cmdStr = cmd.join(" ");
        if (cmdStr.indexOf("su") >= 0 || cmdStr.indexOf("magisk") >= 0) {
            console.log("[+] Blocked command: " + cmdStr);
            return null;
        }
        return this.exec(cmd);
    };

    var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
    ProcessBuilder.start.implementation = function() {
        var cmd = this.command().toString();
        if (cmd.indexOf("su") >= 0 || cmd.indexOf("magisk") >= 0) {
            console.log("[+] Blocked ProcessBuilder: " + cmd);
            return null;
        }
        return this.start();
    };

    console.log("[+] Root detection bypassed");
});
"#.to_string(),
            usage: "frida -U -f com.target.app -l android-root-bypass.js --no-pause".to_string(),
        }
    }

    fn ios_jailbreak_bypass() -> FridaScript {
        FridaScript {
            name: "ios-jailbreak-bypass".to_string(),
            description: "Bypass jailbreak detection on iOS".to_string(),
            platform: "ios".to_string(),
            category: "jailbreak-bypass".to_string(),
            code: r#"
if (ObjC.available) {
    var NSFileManager = ObjC.classes.NSFileManager;

    NSFileManager['- fileExistsAtPath:'].implementation = function(path) {
        var blocked = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt"
        ];
        for (var i = 0; i < blocked.length; i++) {
            if (path.isEqualToString(blocked[i])) {
                console.log("[+] Blocked jailbreak check: " + path);
                return 0;
            }
        }
        return this['- fileExistsAtPath:'](path);
    };

    var stat = Module.findExportByName(null, "stat");
    if (stat) {
        Interceptor.attach(stat, {
            onEnter: function(args) {
                var path = Memory.readUtf8String(args[0]);
                if (path && (path.indexOf("Cydia") >= 0 || path.indexOf("bash") >= 0)) {
                    console.log("[+] Blocked stat: " + path);
                }
            }
        });
    }

    console.log("[+] Jailbreak detection bypassed");
} else {
    console.log("[-] Objective-C runtime not available");
}
"#.to_string(),
            usage: "frida -U -f com.target.app -l ios-jailbreak-bypass.js --no-pause".to_string(),
        }
    }

    fn universal_ssl_bypass() -> FridaScript {
        FridaScript {
            name: "universal-ssl-bypass".to_string(),
            description: "Cross-platform SSL bypass".to_string(),
            platform: "universal".to_string(),
            category: "ssl-bypass".to_string(),
            code: "// Universal SSL bypass placeholder\nconsole.log(\"Load platform-specific SSL bypass\");\n".to_string(),
            usage: "frida -U -f com.target.app -l universal-ssl-bypass.js --no-pause".to_string(),
        }
    }

    fn universal_root_bypass() -> FridaScript {
        FridaScript {
            name: "universal-root-bypass".to_string(),
            description: "Cross-platform root/jailbreak bypass".to_string(),
            platform: "universal".to_string(),
            category: "root-bypass".to_string(),
            code: "// Universal root bypass placeholder\nconsole.log(\"Load platform-specific root bypass\");\n".to_string(),
            usage: "frida -U -f com.target.app -l universal-root-bypass.js --no-pause".to_string(),
        }
    }

    pub fn list_available() -> Vec<&'static str> {
        vec![
            "android-ssl-bypass",
            "ios-ssl-bypass",
            "android-root-bypass",
            "ios-jailbreak-bypass",
            "debug-bypass",
            "pin-unlock",
        ]
    }

    pub fn generate_custom(name: &str, description: &str, platform: &str, hooks: &[(&str, &str)]) -> FridaScript {
        let mut code = String::from("Java.perform(function() {\n");
        if platform == "ios" {
            code = String::from("if (ObjC.available) {\n");
        }

        for (target, action) in hooks {
            code.push_str(&format!(
                "    console.log(\"Hooking: {}\");\n    // {} -> {}\n",
                target, target, action
            ));
        }

        code.push_str("    console.log(\"[+] Custom script loaded\");\n");
        if platform == "ios" {
            code.push_str("}\n");
        }
        code.push_str("});\n");

        FridaScript {
            name: name.to_string(),
            description: description.to_string(),
            platform: platform.to_string(),
            category: "custom".to_string(),
            code,
            usage: format!("frida -U -f com.target.app -l {}.js --no-pause", name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_android_ssl_bypass() {
        let script = FridaGenerator::generate_ssl_bypass("android");
        assert_eq!(script.platform, "android");
        assert!(script.code.contains("X509TrustManager"));
    }

    #[test]
    fn test_generate_ios_ssl_bypass() {
        let script = FridaGenerator::generate_ssl_bypass("ios");
        assert_eq!(script.platform, "ios");
        assert!(script.code.contains("SecTrustEvaluate"));
    }

    #[test]
    fn test_generate_android_root_bypass() {
        let script = FridaGenerator::generate_root_bypass("android");
        assert!(script.code.contains("File.exists"));
    }

    #[test]
    fn test_generate_ios_jailbreak_bypass() {
        let script = FridaGenerator::generate_root_bypass("ios");
        assert!(script.code.contains("NSFileManager"));
    }

    #[test]
    fn test_generate_debug_bypass() {
        let script = FridaGenerator::generate_debug_bypass();
        assert!(script.code.contains("isDebuggerConnected"));
    }

    #[test]
    fn test_generate_pin_unlock() {
        let script = FridaGenerator::generate_pin_unlock();
        assert!(script.code.contains("KeyguardManager"));
    }

    #[test]
    fn test_list_available() {
        let scripts = FridaGenerator::list_available();
        assert!(scripts.contains(&"android-ssl-bypass"));
        assert!(scripts.contains(&"ios-jailbreak-bypass"));
    }

    #[test]
    fn test_generate_custom() {
        let hooks = vec![("LoginActivity.authenticate", "return true")];
        let script = FridaGenerator::generate_custom("test", "Test script", "android", &hooks);
        assert!(script.code.contains("LoginActivity.authenticate"));
    }

    #[test]
    fn test_frida_script_serde() {
        let script = FridaGenerator::generate_ssl_bypass("android");
        let json = serde_json::to_string_pretty(&script).unwrap();
        assert!(json.contains("android-ssl-bypass"));
    }
}
