(function() {
  var element = document.getElementById('rodauth-webauthn-setup-form');
  var f = function(e) {
    //console.log(e);
    e.preventDefault();
    if (navigator.credentials) {
      var opts = JSON.parse(element.getAttribute("data-credential-options"));
      opts.challenge = Uint8Array.from(atob(opts.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
      opts.user.id = Uint8Array.from(atob(opts.user.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
      //console.log(opts);
      navigator.credentials.create({publicKey: opts}).
        then(function(cred){
          //console.log(cred);
          //window.cred = cred
          
          var rawId = btoa(String.fromCharCode.apply(null, new Uint8Array(cred.rawId))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
          document.getElementById('rodauth-webauthn-setup').value = JSON.stringify({
            type: cred.type,
            id: rawId,
            rawId: rawId,
            response: {
              attestationObject: btoa(String.fromCharCode.apply(null, new Uint8Array(cred.response.attestationObject))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
              clientDataJSON: btoa(String.fromCharCode.apply(null, new Uint8Array(cred.response.clientDataJSON))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
            }
          });
          element.removeEventListener("submit", f);
          element.submit();
        }).
        catch(function(e){document.getElementById('rodauth-webauthn-setup-button').innerHTML = "Error creating public key in authenticator: " + e});
    } else {
        document.getElementById('rodauth-webauthn-setup-button').innerHTML = "WebAuthn not supported by browser, or browser has disabled it on this page";
    }
  };
  element.addEventListener("submit", f);
})();
