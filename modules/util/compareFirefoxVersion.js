var EXPORTED_SYMBOLS = ['compareFirefoxVersion'];

function compareFirefoxVersion(aTarget) {
  var appInfo = Components.classes["@mozilla.org/xre/app-info;1"]
      .getService(Components.interfaces.nsIXULAppInfo);
  var versionChecker = Components
      .classes["@mozilla.org/xpcom/version-comparator;1"]
      .getService(Components.interfaces.nsIVersionComparator);

  // SeaMonkey
  return versionChecker.compare(
      (versionChecker.compare(appInfo.version, "35.0") >= 0)
      ? appInfo.version : appInfo.platformVersion, aTarget);
}
