(function() {
  var element = document.getElementById('rodauth-webauthn-auth-form');
  var f = function(e) {
    //console.log(e);
    e.preventDefault();
    if (navigator.credentials) {
      var opts = JSON.parse(element.getAttribute("data-credential-options"));
      opts.challenge = Uint8Array.from(atob(opts.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
      opts.allowCredentials.forEach(function(cred) {
        cred.id = Uint8Array.from(atob(cred.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
      });
      //console.log(opts);
      navigator.credentials.get({publicKey: opts}).
        then(function(cred){
          //console.log(cred);
          //window.cred = cred

          var rawId = btoa(String.fromCharCode.apply(null, new Uint8Array(cred.rawId))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
          var authValue = {
            type: cred.type,
            id: rawId,
            rawId: rawId,
            response: {
              authenticatorData: btoa(String.fromCharCode.apply(null, new Uint8Array(cred.response.authenticatorData))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
              clientDataJSON: btoa(String.fromCharCode.apply(null, new Uint8Array(cred.response.clientDataJSON))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
              signature: btoa(String.fromCharCode.apply(null, new Uint8Array(cred.response.signature))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
            }
          };

          if (cred.response.userHandle) {
            authValue.response.userHandle = btoa(String.fromCharCode.apply(null, new Uint8Array(cred.response.userHandle))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
          }

          document.getElementById('rodauth-webauthn-auth').value = JSON.stringify(authValue);
          element.removeEventListener("submit", f);
          element.submit();
        }).
        catch(function(e){document.getElementById('rodauth-webauthn-auth-button').innerHTML = "Error authenticating using WebauthN: " + e});
    } else {
        document.getElementById('rodauth-webauthn-auth-button').innerHTML = "WebAuthn not supported by browser, or browser has disabled it on this page";
    }
  };
  element.addEventListener("submit", f);
})();

