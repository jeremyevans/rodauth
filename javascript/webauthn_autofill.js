(function() {
  var pack = function(v) { return btoa(String.fromCharCode.apply(null, new Uint8Array(v))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''); };
  var unpack = function(v) { return Uint8Array.from(atob(v.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)); };
  var element = document.getElementById('webauthn-login-form');

  if (!window.PublicKeyCredential || !PublicKeyCredential.isConditionalMediationAvailable) return;

  PublicKeyCredential.isConditionalMediationAvailable().then(function(available) {
    if (!available) return;

    var opts = JSON.parse(element.getAttribute("data-credential-options"));
    opts.challenge = unpack(opts.challenge);
    opts.allowCredentials.forEach(function(cred) { cred.id = unpack(cred.id); });

    navigator.credentials.get({mediation: "conditional", publicKey: opts}).then(function(cred) {
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

      element.submit();
    });
  });
})();

