(function() {
  var pack = function(v) { return btoa(String.fromCharCode.apply(null, new Uint8Array(v))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''); };
  var unpack = function(v) { return Uint8Array.from(atob(v.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)); };
  var element = document.getElementById('webauthn-setup-form');
  var f = function(e) {
    //console.log(e);
    e.preventDefault();
    if (navigator.credentials) {
      var opts = JSON.parse(element.getAttribute("data-credential-options"));
      opts.challenge = unpack(opts.challenge);
      opts.user.id = unpack(opts.user.id);
      opts.excludeCredentials.forEach(function(cred) { cred.id = unpack(cred.id); });
      //console.log(opts);
      navigator.credentials.create({publicKey: opts}).
        then(function(cred){
          //console.log(cred);
          //window.cred = cred

          var rawId = pack(cred.rawId);
          document.getElementById('webauthn-setup').value = JSON.stringify({
            type: cred.type,
            id: rawId,
            rawId: rawId,
            response: {
              attestationObject: pack(cred.response.attestationObject),
              clientDataJSON: pack(cred.response.clientDataJSON)
            }
          });
          element.removeEventListener("submit", f);
          element.submit();
        }).
        catch(function(e){document.getElementById('webauthn-setup-button').innerHTML = "Error creating public key in authenticator: " + e});
    } else {
        document.getElementById('webauthn-setup-button').innerHTML = "WebAuthn not supported by browser, or browser has disabled it on this page";
    }
  };
  element.addEventListener("submit", f);
})();
