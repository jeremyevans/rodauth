# frozen-string-literal: true

module Rodauth
  Feature.define(:webauthn_login, :WebauthnLogin) do
    depends :login, :webauthn

    before

    redirect(:webauthn_login_failure){require_login_redirect}

    error_flash "There was an error authenticating via WebAuthn"

    auth_value_method :webauthn_login_user_verification_additional_factor?, false

    internal_request_method :webauthn_login_params
    internal_request_method :webauthn_login

    route(:webauthn_login) do |r|
      check_already_logged_in
      before_webauthn_login_route

      r.post do
        catch_error do
          unless account_from_webauthn_login && open_account?
            throw_error_reason(:no_matching_login, no_matching_login_error_status, login_param, no_matching_login_message) 
          end

          webauthn_credential = webauthn_auth_credential_from_form_submission
          before_webauthn_login
          login('webauthn') do
            webauthn_update_session(webauthn_credential.id)
            if webauthn_login_verification_factor?(webauthn_credential)
              two_factor_update_session('webauthn-verification')
            end
          end
        end

        set_redirect_error_flash webauthn_login_error_flash
        redirect webauthn_login_failure_redirect
      end
    end

    def webauthn_auth_additional_form_tags
      if @webauthn_login
        super.to_s + login_hidden_field
      else
        super
      end
    end

    def webauthn_auth_form_path
      if @webauthn_login
        webauthn_login_path
      else
        super
      end
    end

    def webauthn_user_verification
      return 'preferred' if webauthn_login_user_verification_additional_factor?
      super
    end

    def use_multi_phase_login?
      true
    end

    private

    def webauthn_login_verification_factor?(webauthn_credential)
      webauthn_login_user_verification_additional_factor? &&
        webauthn_credential.response.authenticator_data.user_verified? &&
        uses_two_factor_authentication?
    end

    def account_from_webauthn_login
      account_from_login(login_param_value)
    end

    def webauthn_login_options?
      !!account_from_webauthn_login
    end

    def _multi_phase_login_forms
      forms = super
      if valid_login_entered? && webauthn_setup?
        @webauthn_login = true
        forms << [20, render('webauthn-auth'), nil]
      end
      forms
    end

    def webauthn_account_id
      super || account_id
    end
  end
end
