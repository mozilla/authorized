
Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");


function AboutOAuthProtocol()
{
}

AboutOAuthProtocol.prototype =
{
  classDescription: "about:oauth",  
  contractID: "@mozilla.org/network/protocol/about;1?what=oauth",  
  classID: Components.ID("739c2b21-ae58-2a4b-b3c5-7a80b7d74ff9"),
  QueryInterface: XPCOMUtils.generateQI([Components.interfaces.nsIAboutModule]),

  getURIFlags: function(aURI) {
    return 0;
  },

  newChannel: function(aURI)
  {
    // aURI is a nsIUri, so get a string from it using .spec
    var ios = Components.classes["@mozilla.org/network/io-service;1"]
                        .getService(Components.interfaces.nsIIOService);
    //var term = aURI.spec.split('?')[1];
    //let uri = ios.newURI("chrome://authorized/content/about.xhtml?input=" + term, null, null);
    var uri = ios.newURI("chrome://authorized/content/about.xhtml", null, null);
    return ios.newChannelFromURI(uri);
  }
}

var components = [AboutOAuthProtocol];
if (XPCOMUtils.generateNSGetFactory)
    var NSGetFactory = XPCOMUtils.generateNSGetFactory(components);
else
    var NSGetModule = XPCOMUtils.generateNSGetModule(components);


