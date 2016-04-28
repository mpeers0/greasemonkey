'use strict';

// Frame scripts, including all their functions, block scopes etc. are
// instantiated for each tab.  Having a single per-process script has a lower
// footprint for stateless things.  Avoid keeping references to frame scripts
// or their content, this could leak frames!

var EXPORTED_SYMBOLS = ['addFrame'];

// PaleMoon
Components.utils.import("resource://gre/modules/Services.jsm");
Components.utils.import("chrome://greasemonkey-modules/content/third-party/extended.js");

// PaleMoon
var _sm_pm_gPalemoonId = "{8de7fcbb-c55c-4fbe-bfc5-fc555c87dbc4}";
if (Services.appinfo.ID != _sm_pm_gPalemoonId) {
  // Each (child) process needs to handle navigation to `.user.js` via file://.
  Components.utils.import("chrome://greasemonkey-modules/content/installPolicy.js");
}

// \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ // \\ //

function addFrame(frameMM) {
  frameMM.addMessageListener("greasemonkey:frame-urls", urlTree);
}


function urlsOfAllFrames(contentWindow) {
  var urls = [contentWindow.location.href];
  function collect(contentWindow) {
    urls = urls.concat(urlsOfAllFrames(contentWindow));
  }
  // Firefox < 32 (i.e. PaleMoon)
  var _sm_pm_tmp = contentWindow.frames;
  (Array.from ? Array.from(_sm_pm_tmp) : _Array.from(_sm_pm_tmp)).forEach(collect);
  return urls;
}


function urlTree(message) {
  var frameMM = message.target;
  var urls = urlsOfAllFrames(frameMM.content);
  var response = {urls: urls};
  frameMM.sendAsyncMessage("greasemonkey:frame-urls", response);
}
