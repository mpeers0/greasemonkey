var EXPORTED_SYMBOLS = ['logError'];

Components.utils.import("chrome://greasemonkey-modules/content/miscapis.js");

var cpmm = Components.classes["@mozilla.org/childprocessmessagemanager;1"]
    .getService(Components.interfaces.nsISyncMessageSender);

var consoleService = Components.classes["@mozilla.org/consoleservice;1"]
    .getService(Components.interfaces.nsIConsoleService);

function logError(e, opt_warn, fileName, lineNumber) {
  if ("string" == typeof e) e = new Error(e);

  var consoleError = Components.classes["@mozilla.org/scripterror;1"]
      .createInstance(Components.interfaces.nsIScriptError);
  // Third parameter "sourceLine" is supposed to be the line, of the source,
  // on which the error happened.  We don't know it.  (Directly...)
  consoleError.init(e.message, fileName, null, lineNumber, e.columnNumber,
      (opt_warn ? 1 : 0), null);
  consoleService.logMessage(consoleError);

  if (WebConsole.Messages) {
    var webConsoleError = new WebConsole.Messages.Simple(e.message, {
      "category": "js",
      "location": {
        "column": e.columnNumber,
        "line": lineNumber,
        "url": fileName
      },
      "severity": (opt_warn ? "warning" : "error")
    });

    cpmm.sendSyncMessage("greasemonkey:web-console-log", {
        "functionName": "GM_util." + logError.name
      }, {
        "message": webConsoleError
      }
    );
  }
}
