

Components.utils.import("resource://authorized/modules/request.js");

window.addEventListener("load", function(e) {
    // add our authorizations list
    var authdom = document.getElementById("authorizations");

    //var div = document.createElement('div');
    //var text = document.createTextNode(JSON.stringify(authorizations.verified));
    //div.appendChild(text);
    //authdom.appendChild(div);

    for (var host in authorizations.verified) {
        var services = authorizations.verified[host];
        var revokeURL = authorizations.getManage(host);
        var div = document.createElement('div');
        var msg = host+" is authorized to "+JSON.stringify(services);
        if (revokeURL) {
            msg = msg +", you can manage your authorizations at ";
        }
        var text = document.createTextNode(msg);
        var a = null;
        if (revokeURL) {
            a = document.createElement('a');
            var link = document.createTextNode(revokeURL);
            a.setAttribute('href', revokeURL);
            a.setAttribute('target', "_blank");
            a.appendChild(link);
        }
        div.appendChild(text);
        if (a) div.appendChild(a);
        authdom.appendChild(div);
    }
}, false);