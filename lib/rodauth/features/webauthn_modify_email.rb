# frozen-string-literal: true

module Rodauth
  Feature.define(:webauthn_modify_email, :WebauthnModifyEmail) do
    depends :webauthn, :email_base

    loaded_templates %w'webauthn-authenticator-added-email webauthn-authenticator-removed-email'
    email :webauthn_authenticator_added, 'WebAuthn Authenticator Added', :translatable=>true
    email :webauthn_authenticator_removed, 'WebAuthn Authenticator Removed', :translatable=>true

    private

    def after_webauthn_setup
      super
      send_webauthn_authenticator_added_email
    end

    def after_webauthn_remove
      super
      send_webauthn_authenticator_removed_email
    end
  end
end
