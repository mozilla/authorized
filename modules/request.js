
const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;
const Cu = Components.utils;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://authorized/modules/log4moz.js");

var EXPORTED_SYMBOLS = ["authorizations"];

var observerService = Cc["@mozilla.org/observer-service;1"].getService(Ci.nsIObserverService);

var authorizations = {
    _log: SimpleLogger.getLogger("oauthObserver", "oauthObserver.txt", true, true, false),
    verified: {}, // this needs to be stored into local storage or something
    manage: {
        "google.com": "https://www.google.com/accounts/IssuedAuthSubTokens",
        "twitter.com": "http://twitter.com/settings/connections",
        "facebook.com": "http://www.facebook.com/editapps.php?v=allowed",
        "yahoo.com": "https://api.login.yahoo.com/WSLogin/V1/unlink",
        "yahooapis.com": "https://api.login.yahoo.com/WSLogin/V1/unlink",
        "linkedin.com": "https://www.linkedin.com/secure/settings?userAgree="
    },
    getManage: function(domain) {
        for (var d in this.manage) {
            if (domain.indexOf(d) >= 0)
                return this.manage[d];
        }
        return null;
    },
    open: function() {
        var file = Components.classes["@mozilla.org/file/local;1"].createInstance(Components.interfaces.nsILocalFile);

        var file = Components.classes["@mozilla.org/file/directory_service;1"]
            .getService(Components.interfaces.nsIProperties)
            .get("ProfD", Components.interfaces.nsIFile);
        file.append("authorized.json");
        if(!file.exists()) {
            file.create(Components.interfaces.nsIFile.NORMAL_FILE_TYPE, 0666);
        }
        return file;
    },
    load: function() {
        this._log.level = Log4Moz.Level.Debug;
        var file = this.open();
        var data = "";
        var fstream = Components.classes["@mozilla.org/network/file-input-stream;1"].
                      createInstance(Components.interfaces.nsIFileInputStream);
        var cstream = Components.classes["@mozilla.org/intl/converter-input-stream;1"].
                      createInstance(Components.interfaces.nsIConverterInputStream);
        fstream.init(file, -1, 0, 0);
        cstream.init(fstream, "UTF-8", 0, 0); // you can use another encoding here if you wish
        
        let (str = {}) {
          let read = 0;
          do { 
            read = cstream.readString(0xffffffff, str); // read as much as we can and put it in str.value
            data += str.value;
          } while (read != 0);
        }
        cstream.close(); // this closes fstream
        
        if (data) {
            this._log.debug('read data '+data);
            this.verified = JSON.parse(data);
        }
    },
    save: function() {
        var file = this.open();
        var data = JSON.stringify(this.verified);
        // file is nsIFile, data is a string
        var foStream = Components.classes["@mozilla.org/network/file-output-stream;1"].
                       createInstance(Components.interfaces.nsIFileOutputStream);
        
        // use 0x02 | 0x10 to open file for appending.
        foStream.init(file, 0x02 | 0x08 | 0x20, 0666, 0); 
        // write, create, truncate
        // In a c file operation, we have no need to set file mode with or operation,
        // directly using "r" or "w" usually.
        
        // if you are sure there will never ever be any non-ascii text in data you can 
        // also call foStream.writeData directly
        var converter = Components.classes["@mozilla.org/intl/converter-output-stream;1"].
                        createInstance(Components.interfaces.nsIConverterOutputStream);
        converter.init(foStream, "UTF-8", 0, 0);
        converter.writeString(data);
        converter.close(); // this closes foStream
    }
}

var oauthObserver = {
    _log: SimpleLogger.getLogger("oauthObserver", "oauthObserver.txt", true, true, false),
    _running: false,
    init: function()
    {
        if (!this._running) {
            authorizations.load();
            observerService.addObserver(this, "quit-application", false);
            observerService.addObserver(this, "http-on-examine-response", false);
            this._running = true;
        }
        this._log.level = Log4Moz.Level.Debug;
        this._log.debug("init OK");
    },

    _shutdown: function()
    {
        observerService.removeObserver(this, "quit-application");
        observerService.removeObserver(this, "http-on-examine-response");
        this._log.debug("shutdown OK");
    },

    /* nsIObserve */
    observe: function(subject, topic, data)
    {
        if (topic == "quit-application") {
            this._shutdown();
            return;
        }

        try {
            if (!(subject instanceof Ci.nsIHttpChannel))
                return;

            if (topic == "http-on-examine-response") {
                this.onModifyRequest(subject, topic, data);
            }
        }
        catch (e) {
            this._log.error("observer EXCEPTION" + e);
        }
    },
    
    onModifyRequest: function(channel) {
        var req = {
            uri: channel.URI.asciiSpec,
            host: channel.URI.host,
            referrer: channel.referrer ? channel.referrer.host : "",
            post: null,
            data: null,
            isOAuth: false,
            isVerified: false
        }
        //this._log.debug("request uri "+req.uri);
        if (channel.requestMethod == "POST") {
            req.post = this.readPostTextFromRequest(channel);
            if (req.post.body.match(/openid/)) {
                // only dig deeper if openid is mentioned in the post data
                if (req.post.headers.match(/application\/x-www-form-urlencoded/)) {
                    req.post.data = this.decodeForm(req.post.body);
                }
                if (req.post.data) {
                    for (var i in req.post.data) {
                        if (req.post.data[i][1] == 'http://specs.openid.net/extensions/oauth/1.0') {
                            this._log.debug("openid+oauth request: "+req.host+" from "+req.referrer);
                            req.isOAuth = true;
                        } else
                        if (req.post.data[i][0] == 'openid.mode' && req.post.data[i][1] == 'id_res') {
                            this._log.debug("openid+oauth request verified: "+req.host+" from "+req.referrer);
                            req.isVerified = true; // still may not be valid
                        }
                    }
                }
            }
        } else {
            if (req.uri.match(/oauth_token=/)) {
                req.isOAuth = true;
                this._log.debug("oauth 1.0 request: "+req.host+" from "+req.referrer);
                if (req.uri.match(/oauth_verifier=/)) {
                    this._log.debug("oauth 1.0 verified: "+req.host+" from "+req.referrer);
                    req.isVerified = true;
                }
            } else
            if (req.uri.match(/client_id=/) && req.uri.match(/redirect_uri=/)) {
                req.isOAuth = true;
                this._log.debug("oauth 2.0 request: "+req.host+" from "+req.referrer);
            } else 
            if (req.uri.match(/code=/)) {
                req.isOAuth = true;
                req.isVerified = true;
                this._log.debug("oauth 2.0 verify: "+req.host+" from "+req.referrer);
            } else
            if (req.uri.match(/openid.mode=id_res/)) {
                this._log.debug("openid+oauth request verified: "+req.host+" from "+req.referrer);
                req.isOAuth = true;
                req.isVerified = true; // still may not be valid
            }
        }
        if (req.isOAuth) {
            // get the window
            if (channel && channel.loadGroup && channel.loadGroup.notificationCallbacks) {
                var lctx = channel.loadGroup.notificationCallbacks.getInterface(Ci.nsILoadContext);
                var win = lctx.associatedWindow;
                this._log.debug("got a window "+win+ " isContent? "+lctx.isContent);


                var xulWindow = win.QueryInterface(Ci.nsIInterfaceRequestor)
                  .getInterface(Ci.nsIWebNavigation)
                                  .QueryInterface(Ci.nsIDocShell)
                                  .chromeEventHandler.ownerDocument.defaultView;
                this._log.debug("got a XUL window "+xulWindow);
                xulWindow = XPCNativeWrapper.unwrap(xulWindow);
                this._log.debug("got an unwrapped XUL window "+xulWindow);

                let gBrowser = xulWindow.gBrowser;
                let _browser = gBrowser.getBrowserForDocument(win.top.document);
                
                if (req.isVerified) {
                    if (!_browser.oauth_request) {
                        this._log.debug("not really an oauth verification");
                        return;
                    }
                    // store the verified data so we can later show the user
                    // what has been stored.
                    var r = _browser.oauth_request ? _browser.oauth_request : req;
                    if (!authorizations.verified[r.host]) {
                        authorizations.verified[r.host] = [];
                    }
                    authorizations.verified[r.host].push(r.referrer);
                    _browser.oauth_request = null;
                    authorizations.save();
                } else {
                    _browser.oauth_request = req;
                }
                
                let nBox = gBrowser.getNotificationBox(_browser);
                let buttons = [
                    {
                    label: "learn more",
                    accessKey: null,
                    callback: function() {
                        xulWindow.openUILinkIn("about:oauth", "tab", null, null, null);;
                    }
                },
                {
                    label: "go away",
                    accessKey: null,
                    callback: function() {
                        gBrowser.getNotificationBox().removeCurrentNotification();
                    }
                }];
                _browser.addEventListener("load", function(e) {
                    nBox.appendNotification(
                                     req.referrer+" is requesting access to your account on "+req.host+".", "OAuth Request",
                                     "chrome://mozapps/skin/passwordmgr/key.png",
                                     nBox.PRIORITY_WARNING_MEDIUM, buttons);
                }, true);

            }
        }
    },
    
    readPostTextFromRequest: function(channel) {
        try {
            var is = channel.QueryInterface(Components.interfaces.nsIUploadChannel).uploadStream;
            if (is) {
                var ss = is.QueryInterface(Components.interfaces.nsISeekableStream);
                var prevOffset;
                if (ss) {
                    prevOffset = ss.tell();
                    ss.seek(Ci.nsISeekableStream.NS_SEEK_SET, 0);
                }
    
                // Read data from the stream..
                //var charset = (context && context.window) ? context.window.document.characterSet : null;
                var charset = null;
                var text = this.readFromStream(is, charset, true);
    
                // Seek locks the file so, seek to the beginning only if necko hasn't read it yet,
                // since necko doesn't seek to 0 before reading (at lest not till 459384 is fixed).
                if (ss && prevOffset == 0)
                    ss.seek(Ci.nsISeekableStream.NS_SEEK_SET, 0);
    
                return text;
            }
        } catch(e) {
            this._log.error("readPostTextFromRequest FAILS "+ e);
        }
        return null;
    },

    readFromStream: function(stream, charset, noClose) {
        //var sis = Components.classes["@mozilla.org/binaryinputstream;1"].createInstance(Components.interfaces.nsIBinaryInputStream);
        //sis.setInputStream(stream);
        var sis = Components.classes["@mozilla.org/scriptableinputstream;1"].createInstance(Components.interfaces.nsIScriptableInputStream);
        sis.init(stream);
    
        var segments = [];
        for (var count = stream.available(); count; count = stream.available())
            segments.push(sis.read(count));
    
        if (!noClose)
            sis.close();
    
        // data[0] is headers, data[1] is body
        var data = segments.join("").split("\r\n\r\n");
        var pd = {
            headers: data.length > 1 ? data[0] : "",
            body: data.length > 1 ? data[1] : data[0]
        }
    
        try {
            return pd;
            //return this.convertToUnicode(text, charset);
        }
        catch (err) {
            this._log.error("readFromStream error" + err);
        }
        return pd;
    },

    decodeForm: function decodeForm(form) {
        var list = [];
        var nvps = form.split('&');
        for (var n = 0; n < nvps.length; ++n) {
            var nvp = nvps[n];
            if (nvp == "") {
                continue;
            }
            var equals = nvp.indexOf('=');
            var name;
            var value;
            if (equals < 0) {
                name = this.decodePercent(nvp);
                value = null;
            } else {
                name = this.decodePercent(nvp.substring(0, equals));
                value = this.decodePercent(nvp.substring(equals + 1));
            }
            list.push([name, value]);
        }
        return list;
    },

    decodePercent: function decodePercent(s) {
        if (s != null) {
            // Handle application/x-www-form-urlencoded, which is defined by
            // http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4.1
            s = s.replace(/\+/g, " ");
        }
        return decodeURIComponent(s);
    }
}

oauthObserver.init();


