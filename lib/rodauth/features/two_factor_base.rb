# frozen-string-literal: true

module Rodauth
  TwoFactorBase = Feature.define(:two_factor_base) do
    after :two_factor_authentication

    redirect :two_factor_auth
    redirect :two_factor_already_authenticated

    notice_flash "You have been authenticated via 2nd factor", "two_factor_auth"

    error_flash "This account has not been setup for two factor authentication", 'two_factor_not_setup'
    error_flash "Already authenticated via 2nd factor", 'two_factor_already_authenticated'
    error_flash "You need to authenticate via 2nd factor before continuing.", 'two_factor_need_authentication'

    auth_value_method :two_factor_already_authenticated_error_status, 403
    auth_value_method :two_factor_need_authentication_error_status, 401
    auth_value_method :two_factor_not_setup_error_status, 403

    auth_value_method :two_factor_session_key, :two_factor_auth
    auth_value_method :two_factor_setup_session_key, :two_factor_auth_setup
    auth_value_method :two_factor_need_setup_redirect, nil

    auth_value_methods(
      :two_factor_auth_required_redirect,
      :two_factor_modifications_require_password?
    )

    auth_methods(
      :two_factor_authenticated?,
      :two_factor_remove,
      :two_factor_remove_auth_failures,
      :two_factor_remove_session,
      :two_factor_update_session
    )

    def two_factor_modifications_require_password?
      modifications_require_password?
    end

    def authenticated?
      super
      two_factor_authenticated? if two_factor_authentication_setup?
    end

    def require_authentication
      super
      require_two_factor_authenticated if two_factor_authentication_setup?
    end

    def require_two_factor_setup
      unless uses_two_factor_authentication?
        set_redirect_error_status(two_factor_not_setup_error_status)
        set_redirect_error_flash two_factor_not_setup_error_flash
        redirect two_factor_need_setup_redirect
      end
    end
    
    def require_two_factor_not_authenticated
      if two_factor_authenticated?
        set_redirect_error_status(two_factor_already_authenticated_error_status)
        set_redirect_error_flash two_factor_already_authenticated_error_flash
        redirect two_factor_already_authenticated_redirect
      end
    end

    def require_two_factor_authenticated
      unless two_factor_authenticated?
        set_redirect_error_status(two_factor_need_authentication_error_status)
        set_redirect_error_flash two_factor_need_authentication_error_flash
        redirect _two_factor_auth_required_redirect
      end
    end

    def two_factor_remove_auth_failures
      nil
    end

    def two_factor_auth_required_redirect
      nil
    end

    def two_factor_auth_fallback_redirect
      nil
    end

    def two_factor_password_match?(password)
      if two_factor_modifications_require_password?
        password_match?(password)
      else
        true
      end
    end

    def two_factor_authenticated?
      !!session[two_factor_session_key]
    end

    def two_factor_authentication_setup?
      false
    end

    def uses_two_factor_authentication?
      return false unless logged_in?
      session[two_factor_setup_session_key] = two_factor_authentication_setup? unless session.has_key?(two_factor_setup_session_key)
      session[two_factor_setup_session_key]
    end

    def two_factor_remove
      nil
    end

    private

    def after_close_account
      super if defined?(super)
      two_factor_remove
    end

    def two_factor_authenticate(type)
      two_factor_update_session(type)
      two_factor_remove_auth_failures
      after_two_factor_authentication
      set_notice_flash two_factor_auth_notice_flash
      redirect two_factor_auth_redirect
    end

    def two_factor_remove_session
      session.delete(two_factor_session_key)
      session[two_factor_setup_session_key] = false
    end

    def two_factor_update_session(type)
      session[two_factor_session_key] = type
      session[two_factor_setup_session_key] = true
    end

    def _two_factor_auth_required_redirect
      two_factor_auth_required_redirect || two_factor_auth_fallback_redirect || default_redirect
    end
  end
end
