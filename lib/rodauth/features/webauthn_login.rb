# frozen-string-literal: true

module Rodauth
  Feature.define(:webauthn_login, :WebauthnLogin) do
    depends :login, :webauthn

    before

    redirect(:webauthn_login_failure){require_login_redirect}

    error_flash "There was an error authenticating via WebAuthn"

    route(:webauthn_login) do |r|
      check_already_logged_in
      before_webauthn_login_route

      r.post do
        catch_error do
          unless account_from_login(param(login_param)) && open_account?
            throw_error_status(no_matching_login_error_status, login_param, no_matching_login_message) 
          end

          webauthn_credential = webauthn_auth_credential_from_form_submission
          before_webauthn_login
          _login('webauthn') do
            webauthn_update_session(webauthn_credential.id)
          end
        end

        set_redirect_error_flash webauthn_login_error_flash
        redirect require_login_redirect
      end
    end

    def webauthn_auth_form_attr
      if @webauthn_login
        "action=\"#{webauthn_login_path}\""
      else
        super
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

    def use_multi_phase_login?
      true
    end

    private

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
