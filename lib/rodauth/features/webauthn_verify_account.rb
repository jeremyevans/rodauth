# frozen-string-literal: true

module Rodauth
  Feature.define(:webauthn_verify_account, :WebauthnVerifyAccount) do
    depends :verify_account, :webauthn

    def verify_account_view
      webauthn_setup_view
    end

    def create_account_set_password?
      false
    end

    def verify_account_set_password?
      false
    end

    def autologin_session(autologin_type)
      super
      if autologin_type == 'verify_account'
        set_session_value(authenticated_by_session_key, ['webauthn'])
        remove_session_value(autologin_type_session_key)
        webauthn_update_session(@webauthn_credential.id)
      end
    end

    private

    def before_verify_account
      super
      if features.include?(:json) && use_json? && !param_or_nil(webauthn_setup_param)
        cred = new_webauthn_credential
        json_response[webauthn_setup_param] = cred.as_json
        json_response[webauthn_setup_challenge_param] = cred.challenge
        json_response[webauthn_setup_challenge_hmac_param] = compute_hmac(cred.challenge)
      end
      @webauthn_credential = webauthn_setup_credential_from_form_submission
      add_webauthn_credential(@webauthn_credential)
    end

    def webauthn_account_id
      super || account_id
    end
  end
end
