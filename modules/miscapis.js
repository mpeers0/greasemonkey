var Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");

Cu.import("chrome://greasemonkey-modules/content/third-party/getChromeWinForContentWin.js");
Cu.import('chrome://greasemonkey-modules/content/prefmanager.js');
Cu.import("chrome://greasemonkey-modules/content/util.js");


var EXPORTED_SYMBOLS = [
    'GM_addStyle', 'GM_console', 'GM_Resources', 'GM_ScriptLogger',
    'WebConsole'];

var cpmm = Components.classes["@mozilla.org/childprocessmessagemanager;1"]
    .getService(Components.interfaces.nsISyncMessageSender);

// \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ //

function WebConsole() {}

var {gDevTools} = Cu.import(
    "resource:///modules/devtools/gDevTools.jsm", {});
var {devtools} = Cu.import(
    "resource://gre/modules/devtools/Loader.jsm", {});

var webConsoleSupport = true;
try {
  // Firefox < 25 (i.e. PaleMoon)
  var {_Messages} = devtools.require(
      "devtools/webconsole/console-output");
} catch (e) {
  webConsoleSupport = false;
}

if (webConsoleSupport) {
  var {Messages} = devtools.require(
      "devtools/webconsole/console-output");

  WebConsole.Messages = Messages;

  WebConsole.getWebConsole = function (tab) {
    if (!tab || !devtools.TargetFactory.isKnownTab(tab)) return null;
    var target = devtools.TargetFactory.forTab(tab);
    // gDevTools.showToolbox(target, "webconsole");
    var toolbox = gDevTools.getToolbox(target);
    var panel = toolbox ? toolbox.getPanel("webconsole") : null;
    return panel ? panel.hud : null;
  }
}

// \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ //

function GM_Resources(script) {
  this.script = script;
  this.stringBundle = Components
    .classes["@mozilla.org/intl/stringbundle;1"]
    .getService(Components.interfaces.nsIStringBundleService)
    .createBundle("chrome://greasemonkey/locale/greasemonkey.properties");
}

GM_Resources.prototype.getResourceURL = function(aScript, name) {
  return ['greasemonkey-script:', aScript.uuid, '/', name].join('');
};

GM_Resources.prototype.getResourceText = function(name) {
  return this._getDep(name).textContent;
};

GM_Resources.prototype._getDep = function(name) {
  var resources = this.script.resources;
  for (var i = 0, resource; resource = resources[i]; i++) {
    if (resource.name == name) {
      return resource;
    }
  }

  throw new Error(
      this.stringBundle.GetStringFromName('error.missingResource')
          .replace('%1', name)
      );
};

// \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ //

function GM_ScriptLogger(script) {
  var namespace = script.namespace;

  if (namespace.substring(namespace.length - 1) != "/") {
    namespace += "/";
  }

  this.prefix = [namespace, script.name, ": "].join("");
}

GM_ScriptLogger.prototype.consoleService = Components
    .classes["@mozilla.org/consoleservice;1"]
    .getService(Components.interfaces.nsIConsoleService);

GM_ScriptLogger.prototype.log = function log(message) {
  // https://developer.mozilla.org/en-US/docs/XPCOM_Interface_Reference/nsIConsoleService#logStringMessage()
  // - wstring / wide string
  message = (this.prefix + '\n' + message).replace(/\0/g, "");

  this.consoleService.logStringMessage(message);

  if (WebConsole.Messages) {
    var message = new WebConsole.Messages.Simple(message.replace(/\n/g, ""), {
      "category": "js",
      "severity": "log"
    });

    cpmm.sendSyncMessage("greasemonkey:web-console-log", {
        "functionName": "GM_" + GM_ScriptLogger.prototype.log.name
      }, {
        "message": message
      }
    );
  }
};

// \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ //

function GM_addStyle(doc, css) {
  var head = doc.getElementsByTagName("head")[0];
  if (head) {
    var style = doc.createElement("style");
    style.textContent = css;
    style.type = "text/css";
    head.appendChild(style);
    return style;
  }
  return null;
}

// \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ //

function GM_console(script) {
  // based on http://www.getfirebug.com/firebug/firebugx.js
  var names = [
    "debug", "warn", "error", "info", "assert", "dir", "dirxml",
    "group", "groupEnd", "time", "timeEnd", "count", "trace", "profile",
    "profileEnd"
  ];

  for (var i=0, name; name=names[i]; i++) {
    this[name] = function() {};
  }

  // Important to use this private variable so that user scripts can't make
  // this call something else by redefining <this> or <logger>.
  var logger = new GM_ScriptLogger(script);
  this.log = function() {
    logger.log(
      Array.prototype.slice.apply(arguments).join("\n")
    );
  };
}

GM_console.prototype.log = function() {
};
