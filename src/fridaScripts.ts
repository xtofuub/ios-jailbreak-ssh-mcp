export type HookType =
  | "network"
  | "request_building"
  | "keychain"
  | "userdefaults"
  | "sqlite"
  | "webview"
  | "deeplinks"
  | "ui_actions"
  | "crypto"
  | "jailbreak_detection";

export const ALL_HOOK_TYPES: HookType[] = [
  "network",
  "request_building",
  "keychain",
  "userdefaults",
  "sqlite",
  "webview",
  "deeplinks",
  "ui_actions",
  "crypto",
  "jailbreak_detection"
];

// ─── Shared preamble injected at the top of every script ────────────────────

const PREAMBLE = `
'use strict';
(function() {
  function se(payload) {
    try { send(payload); } catch(_) {}
  }
  function ss(obj) {
    try { return obj && !obj.isNil() ? obj.toString() : null; } catch(_) { return null; }
  }
  function dictToObj(nsDict) {
    var out = {};
    try {
      var keys = nsDict.allKeys();
      for (var i = 0; i < keys.count(); i++) {
        var k = keys.objectAtIndex_(i);
        var v = nsDict.objectForKey_(k);
        try { out[ss(k)] = ss(v); } catch(_) {}
      }
    } catch(_) {}
    return out;
  }
  function hookObjC(cls, sel, cb) {
    try {
      if (!ObjC.available) return;
      var c = ObjC.classes[cls];
      if (!c) return;
      var m = c[sel];
      if (!m) return;
      Interceptor.attach(m.implementation, { onEnter: cb });
    } catch(_) {}
  }
  function hookC(name, cb) {
    try {
      var addr = Module.findExportByName(null, name);
      if (!addr) return;
      Interceptor.attach(addr, { onEnter: cb });
    } catch(_) {}
  }
  function hookCLeave(name, enterCb, leaveCb) {
    try {
      var addr = Module.findExportByName(null, name);
      if (!addr) return;
      Interceptor.attach(addr, { onEnter: enterCb, onLeave: leaveCb });
    } catch(_) {}
  }
`;

const POSTAMBLE = `
  se({ type: 'hooks_ready' });
})();
`;

// ─── Individual hook category scripts ────────────────────────────────────────

const HOOK_NETWORK = `
  // NSURLSession data/upload/download task creation
  if (ObjC.available) {
    var nsurlSessionMethods = [
      ['NSURLSession', '- dataTaskWithRequest:'],
      ['NSURLSession', '- dataTaskWithRequest:completionHandler:'],
      ['NSURLSession', '- uploadTaskWithRequest:fromData:'],
      ['NSURLSession', '- uploadTaskWithRequest:fromData:completionHandler:'],
      ['NSURLSession', '- downloadTaskWithRequest:'],
      ['NSURLSession', '- downloadTaskWithRequest:completionHandler:']
    ];
    nsurlSessionMethods.forEach(function(pair) {
      hookObjC(pair[0], pair[1], function(args) {
        try {
          var req = new ObjC.Object(args[2]);
          var headers = {};
          try { headers = dictToObj(req.allHTTPHeaderFields()); } catch(_) {}
          var bodySize = 0;
          try { var body = req.HTTPBody(); if (body && !body.isNil()) bodySize = body.length(); } catch(_) {}
          se({ type: 'network', op: pair[1], url: ss(req.URL().absoluteString()), method: ss(req.HTTPMethod()), headers: headers, bodySize: bodySize });
        } catch(_) {}
      });
    });

    // NSURLConnection (legacy)
    hookObjC('NSURLConnection', '+ sendAsynchronousRequest:queue:completionHandler:', function(args) {
      try {
        var req = new ObjC.Object(args[2]);
        se({ type: 'network', op: 'NSURLConnection.sendAsync', url: ss(req.URL().absoluteString()), method: ss(req.HTTPMethod()) });
      } catch(_) {}
    });

    // WKWebView / UIWebView loads via NSURLRequest
    hookObjC('WKWebView', '- loadRequest:', function(args) {
      try {
        var req = new ObjC.Object(args[2]);
        se({ type: 'network', op: 'WKWebView.loadRequest', url: ss(req.URL().absoluteString()) });
      } catch(_) {}
    });
  }
`;

const HOOK_REQUEST_BUILDING = `
  if (ObjC.available) {
    hookObjC('NSMutableURLRequest', '- setHTTPMethod:', function(args) {
      try {
        var self_ = new ObjC.Object(args[0]);
        se({ type: 'request_building', op: 'setHTTPMethod', url: ss(self_.URL().absoluteString()), value: ss(new ObjC.Object(args[2])) });
      } catch(_) {}
    });
    hookObjC('NSMutableURLRequest', '- setValue:forHTTPHeaderField:', function(args) {
      try {
        var self_ = new ObjC.Object(args[0]);
        se({ type: 'request_building', op: 'setHeader', url: ss(self_.URL().absoluteString()), field: ss(new ObjC.Object(args[3])), value: ss(new ObjC.Object(args[2])) });
      } catch(_) {}
    });
    hookObjC('NSMutableURLRequest', '- addValue:forHTTPHeaderField:', function(args) {
      try {
        var self_ = new ObjC.Object(args[0]);
        se({ type: 'request_building', op: 'addHeader', url: ss(self_.URL().absoluteString()), field: ss(new ObjC.Object(args[3])), value: ss(new ObjC.Object(args[2])) });
      } catch(_) {}
    });
    hookObjC('NSMutableURLRequest', '- setHTTPBody:', function(args) {
      try {
        var self_ = new ObjC.Object(args[0]);
        var body = new ObjC.Object(args[2]);
        var sz = 0;
        try { if (body && !body.isNil()) sz = body.length(); } catch(_) {}
        se({ type: 'request_building', op: 'setBody', url: ss(self_.URL().absoluteString()), bodySize: sz });
      } catch(_) {}
    });
    hookObjC('NSMutableURLRequest', '- setURL:', function(args) {
      try {
        se({ type: 'request_building', op: 'setURL', url: ss(new ObjC.Object(args[2]).absoluteString()) });
      } catch(_) {}
    });
  }
`;

const HOOK_KEYCHAIN = `
  // Load Security.framework kSecAttr constants
  function readSecConst(name) {
    try {
      var sym = Module.findExportByName('Security', name);
      if (!sym) return null;
      return Memory.readPointer(sym);
    } catch(_) { return null; }
  }
  var _kSecClass         = readSecConst('kSecClass');
  var _kSecAttrService   = readSecConst('kSecAttrService');
  var _kSecAttrAccount   = readSecConst('kSecAttrAccount');
  var _kSecAttrAccessGrp = readSecConst('kSecAttrAccessGroup');
  var _kSecAttrLabel     = readSecConst('kSecAttrLabel');

  function parseKeychainQuery(ptr_) {
    var out = {};
    try {
      var d = new ObjC.Object(ptr_);
      function gv(k) { try { if (!k) return null; var v = d.objectForKey_(new ObjC.Object(k)); return v && !v.isNil() ? v.toString() : null; } catch(_) { return null; } }
      out.klass       = gv(_kSecClass);
      out.service     = gv(_kSecAttrService);
      out.account     = gv(_kSecAttrAccount);
      out.accessGroup = gv(_kSecAttrAccessGrp);
      out.label       = gv(_kSecAttrLabel);
    } catch(_) {}
    return out;
  }

  ['SecItemCopyMatching','SecItemAdd','SecItemUpdate','SecItemDelete'].forEach(function(fn) {
    hookC(fn, function(args) {
      try {
        se({ type: 'keychain', op: fn, query: parseKeychainQuery(args[0]) });
      } catch(_) {}
    });
  });
`;

const HOOK_USERDEFAULTS = `
  if (ObjC.available) {
    var udGetSels = [
      '- objectForKey:',
      '- stringForKey:',
      '- boolForKey:',
      '- integerForKey:',
      '- floatForKey:',
      '- doubleForKey:',
      '- arrayForKey:',
      '- dictionaryForKey:',
      '- dataForKey:',
      '- URLForKey:'
    ];
    udGetSels.forEach(function(sel) {
      hookObjC('NSUserDefaults', sel, function(args) {
        try {
          se({ type: 'userdefaults', op: 'read', sel: sel, key: ss(new ObjC.Object(args[2])) });
        } catch(_) {}
      });
    });
    var udSetSels = [
      '- setObject:forKey:',
      '- setBool:forKey:',
      '- setInteger:forKey:',
      '- setFloat:forKey:',
      '- setDouble:forKey:',
      '- setURL:forKey:'
    ];
    udSetSels.forEach(function(sel) {
      hookObjC('NSUserDefaults', sel, function(args) {
        try {
          se({ type: 'userdefaults', op: 'write', sel: sel, key: ss(new ObjC.Object(args[3])) });
        } catch(_) {}
      });
    });
    hookObjC('NSUserDefaults', '- removeObjectForKey:', function(args) {
      try {
        se({ type: 'userdefaults', op: 'remove', key: ss(new ObjC.Object(args[2])) });
      } catch(_) {}
    });
    hookObjC('NSUserDefaults', '- synchronize', function(_args) {
      se({ type: 'userdefaults', op: 'synchronize' });
    });
  }
`;

const HOOK_SQLITE = `
  // Track open DB handles → path mapping
  var _dbPaths = {};
  hookC('sqlite3_open', function(args) {
    try {
      var path = args[0].readUtf8String();
      var handlePtr = args[1];
      // store after call — use onLeave pattern via a separate attach
    } catch(_) {}
  });
  hookCLeave('sqlite3_open', function(args) {
    try { this._path = args[0].readUtf8String(); } catch(_) { this._path = null; }
  }, function(retval) {
    try {
      if (retval.toInt32() === 0 && this._path) {
        // Can't easily get db handle here; skip path tracking for now
      }
    } catch(_) {}
  });
  hookCLeave('sqlite3_open_v2', function(args) {
    try { this._path = args[0].readUtf8String(); this._ppDb = args[2]; } catch(_) { this._path = null; }
  }, function(retval) {
    try {
      if (retval.toInt32() === 0 && this._ppDb && this._path) {
        var handle = this._ppDb.readPointer().toString();
        _dbPaths[handle] = this._path;
      }
    } catch(_) {}
  });

  hookC('sqlite3_exec', function(args) {
    try {
      var handle = args[0].toString();
      var sql = args[1].readUtf8String();
      var dbPath = _dbPaths[handle] || null;
      if (sql && sql.trim()) {
        se({ type: 'sqlite', op: 'exec', db: dbPath, sql: sql.slice(0, 500) });
      }
    } catch(_) {}
  });
  hookC('sqlite3_prepare_v2', function(args) {
    try {
      var handle = args[0].toString();
      var sql = args[1].readUtf8String();
      var dbPath = _dbPaths[handle] || null;
      if (sql && sql.trim()) {
        se({ type: 'sqlite', op: 'prepare', db: dbPath, sql: sql.slice(0, 500) });
      }
    } catch(_) {}
  });
  hookC('sqlite3_prepare_v3', function(args) {
    try {
      var handle = args[0].toString();
      var sql = args[1].readUtf8String();
      var dbPath = _dbPaths[handle] || null;
      if (sql && sql.trim()) {
        se({ type: 'sqlite', op: 'prepare_v3', db: dbPath, sql: sql.slice(0, 500) });
      }
    } catch(_) {}
  });
`;

const HOOK_WEBVIEW = `
  if (ObjC.available) {
    hookObjC('WKWebView', '- evaluateJavaScript:completionHandler:', function(args) {
      try {
        var js = ss(new ObjC.Object(args[2]));
        if (js && js.length > 0) {
          se({ type: 'webview', op: 'evaluateJS', js: js.slice(0, 300) });
        }
      } catch(_) {}
    });
    hookObjC('WKWebView', '- evaluateJavaScript:inContentWorld:completionHandler:', function(args) {
      try {
        var js = ss(new ObjC.Object(args[2]));
        if (js) se({ type: 'webview', op: 'evaluateJS_world', js: js.slice(0, 300) });
      } catch(_) {}
    });
    // WKScriptMessageHandler - JS → native messages
    hookObjC('WKUserContentController', '- addScriptMessageHandler:name:', function(args) {
      try {
        se({ type: 'webview', op: 'addMessageHandler', name: ss(new ObjC.Object(args[3])) });
      } catch(_) {}
    });
    // WKNavigationDelegate decidePolicyForNavigationAction
    try {
      var cls = ObjC.classes['WKWebView'];
      if (cls) {
        var sel = '- webView:decidePolicyForNavigationAction:decisionHandler:';
        var m = cls[sel];
        if (m) {
          Interceptor.attach(m.implementation, {
            onEnter: function(args) {
              try {
                var action = new ObjC.Object(args[3]);
                var req = action.request();
                se({ type: 'webview', op: 'navigationPolicy', url: ss(req.URL().absoluteString()) });
              } catch(_) {}
            }
          });
        }
      }
    } catch(_) {}
  }
`;

const HOOK_DEEPLINKS = `
  if (ObjC.available) {
    hookObjC('UIApplication', '- openURL:', function(args) {
      try {
        se({ type: 'deeplinks', op: 'openURL', url: ss(new ObjC.Object(args[2]).absoluteString()) });
      } catch(_) {}
    });
    hookObjC('UIApplication', '- openURL:options:completionHandler:', function(args) {
      try {
        se({ type: 'deeplinks', op: 'openURL_opts', url: ss(new ObjC.Object(args[2]).absoluteString()) });
      } catch(_) {}
    });
    // App delegate handlers
    ['- application:openURL:options:',
     '- application:openURL:sourceApplication:annotation:',
     '- application:handleOpenURL:'].forEach(function(sel) {
      try {
        // These live on the app delegate; hook via UIApplicationDelegate protocol implementors
        var app = ObjC.classes.UIApplication.sharedApplication();
        var delegate = app.delegate();
        if (delegate && !delegate.isNil()) {
          var m = delegate[sel];
          if (m) {
            Interceptor.attach(m.implementation, {
              onEnter: function(args) {
                try {
                  var urlArg = new ObjC.Object(args[3]);
                  se({ type: 'deeplinks', op: 'appDelegate:' + sel, url: ss(urlArg.absoluteString ? urlArg.absoluteString() : urlArg) });
                } catch(_) {}
              }
            });
          }
        }
      } catch(_) {}
    });
  }
`;

const HOOK_UI_ACTIONS = `
  if (ObjC.available) {
    hookObjC('UIControl', '- sendAction:to:from:forEvent:', function(args) {
      try {
        var sel = ObjC.selectorAsString(args[2]);
        var sender = new ObjC.Object(args[0]);
        var target = new ObjC.Object(args[3]);
        se({ type: 'ui_actions', op: 'sendAction', action: sel, senderClass: sender.$className, targetClass: !target.isNil() ? target.$className : null });
      } catch(_) {}
    });
    hookObjC('UIControl', '- sendActionsForControlEvents:', function(args) {
      try {
        var sender = new ObjC.Object(args[0]);
        var events = args[2].toInt32();
        se({ type: 'ui_actions', op: 'sendActionsForControlEvents', senderClass: sender.$className, controlEvents: events });
      } catch(_) {}
    });
    // UIGestureRecognizer state changes
    hookObjC('UIGestureRecognizer', '- setState:', function(args) {
      try {
        var state = args[2].toInt32();
        if (state === 3) { // UIGestureRecognizerStateEnded = 3
          var gr = new ObjC.Object(args[0]);
          se({ type: 'ui_actions', op: 'gestureRecognized', recognizerClass: gr.$className });
        }
      } catch(_) {}
    });
    // UIButton tap
    hookObjC('UIButton', '- sendActionsForControlEvents:', function(args) {
      try {
        var btn = new ObjC.Object(args[0]);
        var title = null;
        try { title = ss(btn.currentTitle()); } catch(_) {}
        var label = null;
        try { label = ss(btn.accessibilityLabel()); } catch(_) {}
        se({ type: 'ui_actions', op: 'buttonTap', title: title, accessibilityLabel: label });
      } catch(_) {}
    });
  }
`;

const HOOK_CRYPTO = `
  // CCCrypt (CommonCrypto)
  hookCLeave('CCCrypt', function(args) {
    try {
      // op: 0=encrypt, 1=decrypt
      var op = args[0].toInt32();
      var alg = args[1].toInt32();
      var options = args[2].toInt32();
      var keyLen = args[4].toInt32();
      this._cryptInfo = { op: op === 0 ? 'encrypt' : 'decrypt', alg: alg, options: options, keyLen: keyLen };
    } catch(_) {}
  }, function(retval) {
    try {
      if (this._cryptInfo) {
        var algNames = { 0: 'AES', 1: '3DES', 2: 'CAST', 3: 'RC4', 5: 'DES', 6: 'Blowfish' };
        this._cryptInfo.algName = algNames[this._cryptInfo.alg] || ('alg_' + this._cryptInfo.alg);
        se({ type: 'crypto', op: 'CCCrypt', info: this._cryptInfo, status: retval.toInt32() });
      }
    } catch(_) {}
  });

  // CCHmac
  hookC('CCHmac', function(args) {
    try {
      var algNames = { 1: 'SHA1', 2: 'MD5', 3: 'SHA256', 4: 'SHA384', 5: 'SHA512', 6: 'SHA224' };
      var alg = args[0].toInt32();
      se({ type: 'crypto', op: 'CCHmac', alg: algNames[alg] || ('alg_' + alg) });
    } catch(_) {}
  });

  // SecKeyCreateSignature
  hookC('SecKeyCreateSignature', function(args) {
    try {
      se({ type: 'crypto', op: 'SecKeyCreateSignature' });
    } catch(_) {}
  });
  hookC('SecKeyCreateEncryptedData', function(args) {
    try {
      se({ type: 'crypto', op: 'SecKeyCreateEncryptedData' });
    } catch(_) {}
  });
  hookC('SecKeyCreateDecryptedData', function(args) {
    try {
      se({ type: 'crypto', op: 'SecKeyCreateDecryptedData' });
    } catch(_) {}
  });

  // MD5 / SHA (libcommonCrypto)
  ['CC_MD5', 'CC_SHA1', 'CC_SHA256', 'CC_SHA512'].forEach(function(fn) {
    hookC(fn, function(_args) {
      se({ type: 'crypto', op: fn });
    });
  });
`;

const HOOK_JAILBREAK_DETECTION = `
  if (ObjC.available) {
    // NSFileManager file existence checks — watch for jailbreak indicator paths
    var jbPaths = new Set([
      '/Applications/Cydia.app','/Applications/Sileo.app','/Applications/Zebra.app',
      '/Applications/Installer.app','/private/var/lib/apt','/private/var/lib/cydia',
      '/usr/sbin/sshd','/usr/bin/ssh','/bin/bash','/etc/apt','/etc/ssh',
      '/var/jb','/var/lib/dpkg','/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist',
      '/.bootstrapped_electra','/.cydia_no_stash','/private/var/mobile/Library/Preferences/cydia.plist',
      '/var/binpack'
    ]);

    hookObjC('NSFileManager', '- fileExistsAtPath:', function(args) {
      try {
        var path = ss(new ObjC.Object(args[2]));
        if (path && jbPaths.has(path)) {
          se({ type: 'jailbreak_detection', op: 'fileExistsAtPath', path: path, checkType: 'jb_file_check' });
        }
      } catch(_) {}
    });
    hookObjC('NSFileManager', '- fileExistsAtPath:isDirectory:', function(args) {
      try {
        var path = ss(new ObjC.Object(args[2]));
        if (path && jbPaths.has(path)) {
          se({ type: 'jailbreak_detection', op: 'fileExistsAtPath:isDirectory:', path: path, checkType: 'jb_file_check' });
        }
      } catch(_) {}
    });

    // canOpenURL for jailbreak URL schemes
    var jbSchemes = new Set(['cydia','sileo','zbra','installer5','apple-magnifier']);
    hookObjC('UIApplication', '- canOpenURL:', function(args) {
      try {
        var url = ss(new ObjC.Object(args[2]).absoluteString());
        if (url) {
          var scheme = url.split(':')[0].toLowerCase();
          if (jbSchemes.has(scheme)) {
            se({ type: 'jailbreak_detection', op: 'canOpenURL', url: url, checkType: 'jb_scheme_check' });
          }
        }
      } catch(_) {}
    });
  }

  // ptrace anti-debug detection
  hookC('ptrace', function(args) {
    try {
      var request = args[0].toInt32();
      // PT_DENY_ATTACH = 31
      se({ type: 'jailbreak_detection', op: 'ptrace', request: request, isDenyAttach: request === 31 });
    } catch(_) {}
  });

  // sysctl - often used to detect debugger
  hookC('sysctl', function(args) {
    try {
      var mib0 = args[0].readInt();
      var mib1 = args[0].add(4).readInt();
      // CTL_KERN=1, KERN_PROC=14 → process info, often used for debug detection
      if (mib0 === 1 && mib1 === 14) {
        se({ type: 'jailbreak_detection', op: 'sysctl', mib: [mib0, mib1], checkType: 'debug_detect' });
      }
    } catch(_) {}
  });

  // dlopen for checking jailbreak dylibs
  hookC('dlopen', function(args) {
    try {
      var path = args[0].readUtf8String();
      if (path) {
        var jbDylibs = ['/usr/lib/libcycript.dylib','/usr/lib/substrate.dylib','/usr/lib/TweakInject.dylib','/var/jb/usr/lib/'];
        var isJb = jbDylibs.some(function(p) { return path.includes(p); });
        if (isJb) {
          se({ type: 'jailbreak_detection', op: 'dlopen', path: path, checkType: 'jb_dylib' });
        }
      }
    } catch(_) {}
  });

  // fork - jailbreak check
  hookC('fork', function(_args) {
    se({ type: 'jailbreak_detection', op: 'fork', checkType: 'sandbox_check' });
  });
`;

// ─── Fast App Listing Scripts ─────────────────────────────────────────────────

export const APPS_LIST_SCRIPT = `
'use strict';
(function() {
  function ss(obj) {
    try { return obj && !obj.isNil() ? obj.toString() : null; } catch(_) { return null; }
  }
  ObjC.schedule(ObjC.mainQueue, function() {
    try {
      var workspace = ObjC.classes.LSApplicationWorkspace.defaultWorkspace();
      var allApps = workspace.allInstalledApplications();
      var apps = [];
      for (var i = 0; i < allApps.count(); i++) {
        var proxy = allApps.objectAtIndex_(i);
        try {
          apps.push({
            bundleId: ss(proxy.applicationIdentifier()),
            name: ss(proxy.localizedName()),
            bundlePath: ss(proxy.bundleURL() ? proxy.bundleURL().path() : null),
            dataPath: ss(proxy.dataContainerURL() ? proxy.dataContainerURL().path() : null),
            version: ss(proxy.bundleVersion()),
            shortVersion: ss(proxy.shortVersionString())
          });
        } catch(_) {}
      }
      send({ type: 'apps', count: apps.length, apps: apps });
    } catch(e) {
      send({ type: 'error', message: e.toString() });
    }
    setTimeout(function() { send({ type: 'done' }); }, 100);
  });
})();
`;

export function buildAppInfoScript(bundleId: string): string {
  const escaped = bundleId.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
  return `
'use strict';
(function() {
  function ss(obj) {
    try { return obj && !obj.isNil() ? obj.toString() : null; } catch(_) { return null; }
  }
  function dictToObj(nsDict) {
    var out = {};
    try {
      if (!nsDict || nsDict.isNil()) return out;
      var keys = nsDict.allKeys();
      for (var i = 0; i < keys.count(); i++) {
        var k = keys.objectAtIndex_(i);
        var v = nsDict.objectForKey_(k);
        try { out[ss(k)] = ss(v); } catch(_) {}
      }
    } catch(_) {}
    return out;
  }
  ObjC.schedule(ObjC.mainQueue, function() {
    try {
      var workspace = ObjC.classes.LSApplicationWorkspace.defaultWorkspace();
      var proxy = workspace.applicationProxyForIdentifier_('${escaped}');
      if (!proxy || proxy.isNil()) {
        send({ type: 'app_info', found: false, bundleId: '${escaped}' });
      } else {
        var info = {
          bundleId: ss(proxy.applicationIdentifier()),
          name: ss(proxy.localizedName()),
          bundlePath: ss(proxy.bundleURL() ? proxy.bundleURL().path() : null),
          dataPath: ss(proxy.dataContainerURL() ? proxy.dataContainerURL().path() : null),
          version: ss(proxy.bundleVersion()),
          shortVersion: ss(proxy.shortVersionString()),
          signerIdentity: ss(proxy.signerIdentity()),
          applicationType: ss(proxy.applicationType()),
          teamID: ss(proxy.teamID()),
          isContainerized: false,
          entitlements: {}
        };
        try { info.isContainerized = proxy.isContainerized(); } catch(_) {}
        try {
          var ent = proxy.entitlements();
          if (ent && !ent.isNil()) info.entitlements = dictToObj(ent);
        } catch(_) {}
        try {
          var groups = proxy.groupContainerURLs();
          if (groups && !groups.isNil()) info.appGroups = dictToObj(groups);
        } catch(_) {}
        try {
          var plugins = proxy.plugInKitPlugins();
          if (plugins && !plugins.isNil()) {
            info.plugins = [];
            var keys = plugins.allKeys();
            for (var i = 0; i < keys.count(); i++) {
              info.plugins.push(ss(keys.objectAtIndex_(i)));
            }
          }
        } catch(_) {}
        send({ type: 'app_info', found: true, info: info });
      }
    } catch(e) {
      send({ type: 'error', message: e.toString() });
    }
    setTimeout(function() { send({ type: 'done' }); }, 100);
  });
})();
`;
}

// ─── UI Automation Scripts ────────────────────────────────────────────────────

export const UI_DUMP_SCRIPT = `
'use strict';
(function() {
  function ss(obj) {
    try { return obj && !obj.isNil() ? obj.toString() : null; } catch(_) { return null; }
  }
  function dumpView(view, depth) {
    if (depth > 12) return null;
    var out = { cls: view.$className };
    try {
      var f = view.frame();
      out.frame = { x: f.origin.x, y: f.origin.y, w: f.size.width, h: f.size.height };
    } catch(_) {}
    try { out.label = ss(view.accessibilityLabel()); } catch(_) {}
    try { out.id = ss(view.accessibilityIdentifier()); } catch(_) {}
    try { out.hidden = view.isHidden(); } catch(_) {}
    try {
      if (view.respondsToSelector_(ObjC.selector('currentTitle'))) {
        out.title = ss(view.currentTitle());
      }
    } catch(_) {}
    try {
      if (view.respondsToSelector_(ObjC.selector('text'))) {
        out.text = ss(view.text());
      }
    } catch(_) {}
    try {
      if (view.respondsToSelector_(ObjC.selector('isEnabled'))) {
        out.enabled = view.isEnabled();
      }
    } catch(_) {}
    try {
      var subs = view.subviews();
      var count = subs.count();
      if (count > 0) {
        out.children = [];
        for (var i = 0; i < Math.min(count, 50); i++) {
          var child = dumpView(subs.objectAtIndex_(i), depth + 1);
          if (child) out.children.push(child);
        }
      }
    } catch(_) {}
    return out;
  }

  ObjC.schedule(ObjC.mainQueue, function() {
    try {
      var result = [];
      var windows = ObjC.classes.UIApplication.sharedApplication().windows();
      for (var i = 0; i < windows.count(); i++) {
        var w = dumpView(windows.objectAtIndex_(i), 0);
        if (w) result.push(w);
      }
      send({ type: 'ui_hierarchy', windows: result });
    } catch(e) {
      send({ type: 'error', message: e.toString() });
    }
    // Exit after dump
    setTimeout(function() { send({ type: 'done' }); }, 100);
  });
})();
`;

export interface UiMatcher {
  accessibilityLabel?: string;
  accessibilityIdentifier?: string;
  className?: string;
  title?: string;
  text?: string;
  index?: number;
}

export function buildUiTapScript(matcher: UiMatcher): string {
  const matcherJson = JSON.stringify(matcher);
  return `
'use strict';
(function() {
  var matcher = ${matcherJson};
  function ss(obj) {
    try { return obj && !obj.isNil() ? obj.toString() : null; } catch(_) { return null; }
  }
  function matchesView(view) {
    try {
      if (matcher.accessibilityLabel) {
        var lbl = ss(view.accessibilityLabel());
        if (lbl && lbl.toLowerCase() === matcher.accessibilityLabel.toLowerCase()) return true;
      }
      if (matcher.accessibilityIdentifier) {
        var ident = ss(view.accessibilityIdentifier());
        if (ident && ident === matcher.accessibilityIdentifier) return true;
      }
      if (matcher.className) {
        if (view.$className === matcher.className) return true;
      }
      if (matcher.title) {
        if (view.respondsToSelector_(ObjC.selector('currentTitle'))) {
          var t = ss(view.currentTitle());
          if (t && t.toLowerCase() === matcher.title.toLowerCase()) return true;
        }
      }
      if (matcher.text) {
        if (view.respondsToSelector_(ObjC.selector('text'))) {
          var tx = ss(view.text());
          if (tx && tx.toLowerCase() === matcher.text.toLowerCase()) return true;
        }
      }
    } catch(_) {}
    return false;
  }
  function findInView(view, results) {
    try {
      if (matchesView(view)) {
        results.push(view);
        if (results.length >= 10) return;
      }
      var subs = view.subviews();
      for (var i = 0; i < subs.count(); i++) {
        findInView(subs.objectAtIndex_(i), results);
        if (results.length >= 10) return;
      }
    } catch(_) {}
  }
  function tapView(view) {
    var info = { cls: view.$className };
    try { info.label = ss(view.accessibilityLabel()); } catch(_) {}
    try {
      if (view.respondsToSelector_(ObjC.selector('sendActionsForControlEvents:'))) {
        view.sendActionsForControlEvents_(64); // UIControlEventTouchUpInside
        send({ type: 'tapped', element: info, method: 'sendActions' });
        return true;
      }
    } catch(_) {}
    try {
      if (view.respondsToSelector_(ObjC.selector('accessibilityActivate'))) {
        var didActivate = view.accessibilityActivate();
        send({ type: 'tapped', element: info, method: 'accessibilityActivate', activated: didActivate });
        return true;
      }
    } catch(_) {}
    send({ type: 'tap_failed', element: info, reason: 'no_tap_method' });
    return false;
  }

  ObjC.schedule(ObjC.mainQueue, function() {
    try {
      var matches = [];
      var windows = ObjC.classes.UIApplication.sharedApplication().windows();
      for (var i = windows.count() - 1; i >= 0; i--) {
        findInView(windows.objectAtIndex_(i), matches);
        if (matches.length >= 10) break;
      }
      var idx = matcher.index || 0;
      if (matches.length === 0) {
        send({ type: 'not_found', matcher: matcher });
      } else if (idx >= matches.length) {
        send({ type: 'index_out_of_range', matcher: matcher, found: matches.length, requestedIndex: idx });
      } else {
        tapView(matches[idx]);
      }
    } catch(e) {
      send({ type: 'error', message: e.toString() });
    }
    setTimeout(function() { send({ type: 'done' }); }, 200);
  });
})();
`;
}

// ─── Hook script builder ──────────────────────────────────────────────────────

const HOOK_SCRIPTS: Record<HookType, string> = {
  network: HOOK_NETWORK,
  request_building: HOOK_REQUEST_BUILDING,
  keychain: HOOK_KEYCHAIN,
  userdefaults: HOOK_USERDEFAULTS,
  sqlite: HOOK_SQLITE,
  webview: HOOK_WEBVIEW,
  deeplinks: HOOK_DEEPLINKS,
  ui_actions: HOOK_UI_ACTIONS,
  crypto: HOOK_CRYPTO,
  jailbreak_detection: HOOK_JAILBREAK_DETECTION
};

export function buildHookScript(hookTypes: HookType[]): string {
  const parts: string[] = [PREAMBLE];
  for (const type of hookTypes) {
    const script = HOOK_SCRIPTS[type];
    if (script) {
      parts.push(`  // ---- ${type.toUpperCase()} ----`);
      parts.push(script.trim());
    }
  }
  parts.push(POSTAMBLE);
  return parts.join("\n\n");
}
