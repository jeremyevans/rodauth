(function() {
  var pack = function(v) { return btoa(String.fromCharCode.apply(null, new Uint8Array(v))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''); };
  var unpack = function(v) { return Uint8Array.from(atob(v.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)); };
  var element = document.getElementById('webauthn-auth-form');
  var f = function(e) {
    //console.log(e);
    e.preventDefault();
    if (navigator.credentials) {
      var opts = JSON.parse(element.getAttribute("data-credential-options"));
      opts.challenge = unpack(opts.challenge);
      opts.allowCredentials.forEach(function(cred) { cred.id = unpack(cred.id); });
      //console.log(opts);
      navigator.credentials.get({publicKey: opts}).
        then(function(cred){
          //console.log(cred);
          //window.cred = cred

          var rawId = pack(cred.rawId);
          var authValue = {
            type: cred.type,
            id: rawId,
            rawId: rawId,
            response: {
              authenticatorData: pack(cred.response.authenticatorData),
              clientDataJSON: pack(cred.response.clientDataJSON),
              signature: pack(cred.response.signature)
            }
          };

          if (cred.response.userHandle) {
            authValue.response.userHandle = pack(cred.response.userHandle);
          }

          document.getElementById('webauthn-auth').value = JSON.stringify(authValue);
          element.removeEventListener("submit", f);
          element.submit();
        }).
        catch(function(e){document.getElementById('webauthn-auth-button').innerHTML = "Error authenticating using WebAuthn: " + e});
    } else {
        document.getElementById('webauthn-auth-button').innerHTML = "WebAuthn not supported by browser, or browser has disabled it on this page";
    }
  };
  element.addEventListener("submit", f);
})();

