'use strict';

var EXPORTED_SYMBOLS = [];

var Cc = Components.classes;
var Ci = Components.interfaces;
var Cu = Components.utils;
var Cr = Components.results;

Cu.import("resource://gre/modules/Services.jsm");

Cu.import("chrome://greasemonkey-modules/content/util.js");
Cu.import("chrome://greasemonkey-modules/content/prefmanager.js");

var gDisallowedSchemes = {
    'chrome': 1, 'greasemonkey-script': 1, 'view-source': 1};
var gScriptEndingRegexp = new RegExp('\\.user\\.js$');
var gContentTypes = Ci.nsIContentPolicy;

var gCspObservers = [
  "http-on-examine-response",
  "http-on-examine-cached-response",
  // "http-on-examine-merged-response"
];


// \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ //

function checkScriptRefresh(channel) {
  // .loadInfo is part of nsiChannel -> implicit QI needed
  if (!(channel instanceof Components.interfaces.nsIChannel)) return;
  if (!channel.loadInfo) return;

  // See http://bugzil.la/1182571
  var type = channel.loadInfo.externalContentPolicyType
      ? channel.loadInfo.externalContentPolicyType
      : channel.loadInfo.contentPolicyType;

  // only check for updated scripts when tabs/iframes are loaded
  if (type != gContentTypes.TYPE_DOCUMENT
      && type != gContentTypes.TYPE_SUBDOCUMENT
  ) {
    return;
  }

  // forward compatibility: https://bugzilla.mozilla.org/show_bug.cgi?id=1124477
  var browser = channel.loadInfo.topFrameElement;

  if (!browser && channel.notificationCallbacks) {
    // current API: https://bugzilla.mozilla.org/show_bug.cgi?id=1123008#c7
    var loadCtx = channel.notificationCallbacks.QueryInterface(
        Components.interfaces.nsIInterfaceRequestor).getInterface(
        Components.interfaces.nsILoadContext);
    browser = loadCtx.topFrameElement;
  }

  var windowId = channel.loadInfo.innerWindowID;

  GM_util.getService().scriptRefresh(channel.URI.spec, windowId, browser);
}

// \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ //

function installObserver(aSubject, aTopic, aData) {
  // When observing a new request, inspect it to determine if it should be
  // a user script install.  If so, abort and restart as an install rather
  // than a navigation.
  if (!GM_util.getEnabled()) {
    return;
  }

  var channel = aSubject.QueryInterface(Ci.nsIChannel);
  if (!channel || !channel.loadInfo) {
    return;
  }

  // See http://bugzil.la/1182571
  var type = channel.loadInfo.externalContentPolicyType
      || channel.loadInfo.contentPolicyType;
  if (type != gContentTypes.TYPE_DOCUMENT) {
    return;
  }

  if (channel.URI.scheme in gDisallowedSchemes) {
    return;
  }

  try {
    var httpChannel = channel.QueryInterface(Ci.nsIHttpChannel);
    if ('POST' == httpChannel.requestMethod) {
      return;
    }
  } catch (e) {
    // Ignore completely, e.g. file:/// URIs.
  }

  if (!channel.URI.spec.match(gScriptEndingRegexp)) {
    return;
  }

  // We've done an early return above for all non-user-script navigations.  If
  // execution has proceeded to this point, we want to cancel the existing
  // request (i.e. navigation) and instead start a script installation for
  // this same URI.
  try {
    var request = channel.QueryInterface(Ci.nsIRequest);
    request.suspend();

    var browser = channel
        .QueryInterface(Ci.nsIHttpChannel)
        .notificationCallbacks
        .getInterface(Ci.nsILoadContext)
        .topFrameElement;

    GM_util.showInstallDialog(channel.URI.spec, browser, request);
  } catch (e) {
    dump('Greasemonkey could not do script install!\n'+e+'\n');
    // Ignore.
    return;
  }
}

// \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ //

function cspObserver(aSubject, aTopic, aData) {
  if (!GM_util.getEnabled()) {
    return;
  }

  var channel = aSubject.QueryInterface(Ci.nsIChannel);
  if (!channel) {
    return;
  }

  // dump("cspObserver - observer (" + aTopic + ") - url: " + channel.URI.spec + "\n");
  try {
    var httpChannel = channel.QueryInterface(Ci.nsIHttpChannel);
    // dump("cspObserver - httpChannel - responseStatus: " + httpChannel.responseStatus + "\n");
    if (200 != httpChannel.responseStatus) {
      return;
    }
  } catch (e) {
    // dump("cspObserver - httpChannel - file:/// URIs? - e: " + e + "\n");
    return;
  }

  var cspHeader1 = "Content-Security-Policy";
  var cspHeader2 = "X-Content-Security-Policy";

  var cspRules = null;
  var cspRulesMy = null;

  try {    
    cspRules = channel.getResponseHeader(cspHeader1);
    // dump("cspObserver - header (" + cspHeader1 + ") - before: " + cspRules + "\n");
    cspRulesMy = _cspOverride(cspRules);
    channel.setResponseHeader(cspHeader1, cspRulesMy, false);
    cspRules = channel.getResponseHeader(cspHeader1);
    // dump("cspObserver - header (" + cspHeader1 + ") - after: " + cspRules + "\n");
  } catch (e) {
    try {
      cspRules = channel.getResponseHeader(cspHeader2);
      // dump("cspObserver - header (" + cspHeader2 + ") - before: " + cspRules + "\n");
      cspRulesMy = _cspOverride(cspRules);
      channel.setResponseHeader(cspHeader2, cspRulesMy, false);
      cspRules = channel.getResponseHeader(cspHeader2);
      // dump("cspObserver - header (" + cspHeader2 + ") - after: " + cspRules + "\n");
    } catch (e) {
      // dump("cspObserver - no csp headers defined? - e: " + e + "\n");
      return;
    }
  }
}

function _cspOverride(aCspRules) {
  var rules = aCspRules.split(";");

  var rulesMyDefault = ["'unsafe-inline'", "'unsafe-eval'"];

  // base-uri, child-src, connect-src, font-src, form-action,
  // frame-ancestors, frame-src, img-src, manifest-src, media-src,
  // object-src, plugin-types, referrer, reflected-xss, report-uri,
  // sandbox, script-src, strict-dynamic, style-src, upgrade-insecure-requests
  var rulesMy = [
    /*
    {
      "name": "base-uri",
      "value": rulesMyDefault,
      "noDefaultOverride": false
    },
    {
      "name": "child-src",
      "value": rulesMyDefault,
      "noDefaultOverride": false
    },
    {
      "name": "connect-src",
      "value": rulesMyDefault,
      "noDefaultOverride": false
    },
    {
      "name": "font-src",
      "value": rulesMyDefault,
      "noDefaultOverride": false
    },
    {
      "name": "form-action",
      "value": rulesMyDefault,
      "noDefaultOverride": false
    },
    {
      "name": "frame-ancestors",
      "value": rulesMyDefault,
      "noDefaultOverride": false
    },
    {
      "name": "frame-src",
      "value": rulesMyDefault,
      "noDefaultOverride": false
    },
    {
      "name": "img-src",
      "value": rulesMyDefault,
      "noDefaultOverride": false
    },
    {
      "name": "manifest-src",
      "value": rulesMyDefault,
      "noDefaultOverride": false
    },
    {
      "name": "media-src",
      "value": rulesMyDefault,
      "noDefaultOverride": false
    },
    {
      "name": "object-src",
      "value": rulesMyDefault,
      "noDefaultOverride": false
    },
    {
      "name": "refferer",
      "value": "unsafe-url",
      "noDefaultOverride": false
    },
    */
    {
      "name": "script-src",
      "value": rulesMyDefault,
      // "noDefaultOverride": true
      "noDefaultOverride": false
    },
    /*
    {
      "name": "style-src",
      "value": rulesMyDefault,
      "noDefaultOverride": false
    },
    */
  ];

  var ruleDefault = {
    "index": -1,
    "override": true,
    "value": "default-src"
  };

  // http://www.w3.org/TR/CSP2/#directive-script-src
  // http://www.w3.org/TR/CSP2/#source-list-syntax
  // http://bugzil.la/1004703, http://bugzil.la/1026520, etc.
  // - Content Security Policy: Ignoring “'unsafe-inline'”
  //   within script-src or style-src: nonce-source or hash-source specified
  // e.g.: https://twitter.com
  var rulesDisabled = new RegExp(
      "\\s?'(none|(nonce|sha256|sha384|sha512)-[^']+)'", "gim");

  for (var i = 0, i_count = rules.length; i < i_count; i++) {
    if (rules[i].trim() != "") {
      // dump("cspObserver - rules: " + rules[i].trim() + "\n");
      for (var j = 0, j_count = rulesMy.length; j < j_count; j++) {
        if (rules[i].toLowerCase().trim().indexOf(rulesMy[j].name) == 0) {
          // dump("cspObserver - rules - my (" + rulesMy[j].name + ") - before: " + rules[i] + "\n");
          if (rulesDisabled.test(rules[i])) {
            // dump("cspObserver - rules - my (" + rulesMy[j].name + ") - disabled" + "\n");
            rules[i] = rules[i].replace(rulesDisabled, "");
          }
          for (var k = 0, k_count = rulesMy[j].value.length; k < k_count; k++) {
            if (rules[i].toLowerCase().indexOf(rulesMy[j].value[k]) == -1) {
              rules[i] = rules[i] + " " + rulesMy[j].value[k];
            }
          }
          // dump("cspObserver - rules - my (" + rulesMy[j].name + ") - after: " + rules[i] + "\n");
          if (ruleDefault.override) {
            ruleDefault.override = !rulesMy[j].noDefaultOverride;
          }
          // break;
        }
      }
      if (rules[i].toLowerCase().trim().indexOf(ruleDefault.value) == 0) {
        // dump("cspObserver - rules - default (" + rules[i].trim() + ") - index: " + i + "\n");
        ruleDefault.index = i;
      }
    }
  }
  if (ruleDefault.override && (ruleDefault.index != -1)) {
    // dump("cspObserver - rules - default (" + ruleDefault.value + ") - before: " + rules[ruleDefault.index] + "\n");
    if (rulesDisabled.test(rules[ruleDefault.index])) {
      // dump("cspObserver - rules - default (" + ruleDefault.value + ") - disabled" + "\n");
      rules[ruleDefault.index] = rules[ruleDefault.index]
          .replace(rulesDisabled, "");
    }
    for (var j = 0, j_count = rulesMyDefault.length; j < j_count; j++) {
      if (rules[ruleDefault.index]
          .toLowerCase().indexOf(rulesMyDefault[j]) == -1) {
        rules[ruleDefault.index] = rules[ruleDefault.index]
            + " " + rulesMyDefault[j];
      }
    }
    // dump("cspObserver - rules - default (" + ruleDefault.value + ") - after: " + rules[ruleDefault.index] + "\n");
  }

  return rules.join(";");
}

// \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ //

Services.obs.addObserver({
  observe: function(aSubject, aTopic, aData) {
    try {
      installObserver(aSubject, aTopic, aData);
    } catch (e) {
      dump('Greasemonkey install observer failed:\n' + e + '\n');
    }
    try {
      checkScriptRefresh(aSubject);
    } catch (e) {
      dump('Greasemonkey refresh observer failed:\n' + e + '\n');
    }
  }
}, "http-on-modify-request", false);

for (var observer in gCspObservers) {
  Services.obs.addObserver({
    observe: function(aSubject, aTopic, aData) {
      try {
        cspObserver(aSubject, aTopic, aData);
      } catch (e) {
        dump("Greasemonkey install observer failed:\n" + e + "\n");
      }
    }
  }, gCspObservers[observer], false);
}
