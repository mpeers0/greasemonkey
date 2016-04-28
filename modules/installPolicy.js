// Firefox < 35 (i.e. PaleMoon)
// https://bugzilla.mozilla.org/show_bug.cgi?id=1038756
// Firefox < 38 (i.e. PaleMoon)
// https://bugzilla.mozilla.org/show_bug.cgi?id=1123008

// This module is responsible for observing HTTP traffic, detecting when a user
// script is loaded (e.g. a link to one is clicked), and launching the install
// dialog instead.

// This module is responsible for detecting user scripts that are loaded by
// some means OTHER than HTTP (which the http-on-modify-request observer
// handles), i.e. local files.

var EXPORTED_SYMBOLS = ["_sm_pm_passNextScript"];

var Cc = Components.classes;
var Ci = Components.interfaces;
var Cu = Components.utils;
var Cr = Components.results;

Cu.import('resource://gre/modules/Services.jsm');
Cu.import('resource://gre/modules/XPCOMUtils.jsm');

Cu.import('chrome://greasemonkey-modules/content/util.js');

var gHaveDoneInit = false;
var gScriptEndingRegexp = new RegExp('\\.user\\.js$');

XPCOMUtils.defineLazyServiceGetter(
    this, 'cpmm',
    '@mozilla.org/childprocessmessagemanager;1', 'nsIMessageSender');

////////////////////////////////////////////////////////////////////////////////

// PaleMoon
var _sm_pm_gPalemoonId = "{8de7fcbb-c55c-4fbe-bfc5-fc555c87dbc4}";
var _sm_pm_gPassNextScript = false;
function _sm_pm_passNextScript() {
  _sm_pm_gPassNextScript = true;
}

////////////////////////////////////////////////////////////////////////////////

var InstallPolicy = {
  _classDescription: 'Greasemonkey Script Install Policy',
  _classID: Components.ID('c03c575c-e87e-4a0f-b88d-8be090116a0c'),
  _contractID: '@greasemonkey.mozdev.org/greasemonkey-install-policy;1',

  init: function() {
    try {
      var registrar = Components.manager.QueryInterface(Ci.nsIComponentRegistrar);
      registrar.registerFactory(
          this._classID, this._classDescription, this._contractID, this);
    } catch (e) {
      if ('NS_ERROR_FACTORY_EXISTS' == e.name) {
        // No-op, ignore these.  But why do they happen!?
      } else {
        dump('Error registering InstallPolicy factory:\n' + e + '\n');
      }
      return;
    }

    var catMan = Cc["@mozilla.org/categorymanager;1"]
        .getService(Ci.nsICategoryManager);
    catMan.addCategoryEntry(
        'content-policy', this._contractID, this._contractID, false, true);
  },

  QueryInterface: XPCOMUtils.generateQI([
      Ci.nsIContentPolicy,
      Ci.nsIFactory,
      Ci.nsISupportsWeakReference
      ]),

/////////////////////////////// nsIContentPolicy ///////////////////////////////

  shouldLoad: function(aContentType, aContentURI, aOriginURI, aContext) {
    var ACCEPT = Ci.nsIContentPolicy.ACCEPT;
    var REJECT = Ci.nsIContentPolicy.REJECT_REQUEST;

    // PaleMoon
    if (Services.appinfo.ID != _sm_pm_gPalemoonId) {
      // Ignore everything that isn't a file:// .
      if ('file' != aContentURI.scheme) {
        return ACCEPT;
      }
    } else {
      // Don't interrupt the "view-source:" scheme (which is triggered
      // if the link in the error console is clicked),
      // nor the "greasemonkey-script:" scheme.
      // Never break chrome.
      if ("view-source" == aContentURI.scheme
          || "chrome" == aContentURI.scheme
          || "greasemonkey-script" == aContentURI.scheme) {
        return ACCEPT;
      }
    }
    // Ignore everything that isn't a top-level document navigation.
    if (aContentType != Ci.nsIContentPolicy.TYPE_DOCUMENT) {
      return ACCEPT;
    }
    // Ignore everything when GM is not enabled.
    if (!GM_util.getEnabled()) {
      return ACCEPT;
    }
    // PaleMoon
    if (Services.appinfo.ID == _sm_pm_gPalemoonId) {
      // Do not install scripts when the origin URL "is a script".  See #1875
      if (aOriginURI && aOriginURI.spec.match(gScriptEndingRegexp)) {
        return ACCEPT;
      }
    }
    // Ignore everything that isn't a user script.
    if (!aContentURI.spec.match(gScriptEndingRegexp)) {
      return ACCEPT;
    }
    // PaleMoon
    if (_sm_pm_gPassNextScript) { 
      // E.g. Detected HTML content so forced re-navigation.
      _sm_pm_gPassNextScript = false;
      return ACCEPT;
    }
    // Ignore temporary files, e.g. "Show script source".
    // PaleMoon
    if (Services.appinfo.ID == _sm_pm_gPalemoonId) {
      delete cpmm;
      // With e10s off, context is a <browser> with a direct reference to
      // the docshell loaded therein.
      var _sm_pm_docShell = aContext && aContext.docShell;

      if (!_sm_pm_docShell) {
        // But with e10s on, context is a content window and we have to work
        // hard to find the docshell, from which we can find
        // the message manager.
        _sm_pm_docShell = aContext
            .QueryInterface(Ci.nsIInterfaceRequestor)
            .getInterface(Ci.nsIWebNavigation)
            .QueryInterface(Ci.nsIDocShellTreeItem).rootTreeItem;
      }

      try {
        // Do not use "var"
        // Firefox - the Browser Console: cpmm is undefined
        cpmm = _sm_pm_docShell
            .QueryInterface(Ci.nsIInterfaceRequestor)
            .getInterface(Ci.nsIContentFrameMessageManager);
      } catch (e) {
        return ACCEPT;
      }
    }
    var tmpResult = cpmm.sendSyncMessage(
        'greasemonkey:url-is-temp-file', {'url': aContentURI.spec});
    if (tmpResult.length && tmpResult[0]) {
      return ACCEPT;
    }

    // PaleMoon
    if (Services.appinfo.ID != _sm_pm_gPalemoonId) {
      cpmm.sendAsyncMessage(
          'greasemonkey:script-install', {'url': aContentURI.spec});
    } else {
      cpmm.sendAsyncMessage( 
          'greasemonkey:script-install', {
            'referer': aOriginURI ? aOriginURI.spec : null,
            'url': aContentURI.spec
          });
    }
    return REJECT;
  },

  shouldProcess: function() {
    return Ci.nsIContentPolicy.ACCEPT;
  },

////////////////////////////////// nsIFactory //////////////////////////////////

  createInstance: function(outer, iid) {
    if (outer) {
      throw Cr.NS_ERROR_NO_AGGREGATION;
    }
    return this.QueryInterface(iid);
  },
};

////////////////////////////////////////////////////////////////////////////////

if (!gHaveDoneInit) {
  gHaveDoneInit = true;
  InstallPolicy.init();
}
