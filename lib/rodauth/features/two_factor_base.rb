# frozen-string-literal: true

module Rodauth
  Feature.define(:two_factor_base, :TwoFactorBase) do
    loaded_templates %w'two-factor-manage two-factor-auth two-factor-disable'

    view 'two-factor-manage', 'Manage Two Factor Authentication', 'two_factor_manage'
    view 'two-factor-auth', 'Authenticate Using 2nd Factor', 'two_factor_auth'
    view 'two-factor-disable', 'Remove All 2nd Factor Authentication Methods', 'two_factor_disable'

    before :two_factor_disable

    after :two_factor_authentication
    after :two_factor_disable

    additional_form_tags :two_factor_disable

    button "Remove All 2nd Factor Authentication Methods", :two_factor_disable

    redirect(:two_factor_auth)
    redirect(:two_factor_already_authenticated)
    redirect(:two_factor_disable)
    redirect(:two_factor_need_setup){two_factor_manage_path}
    redirect(:two_factor_auth_required){two_factor_auth_path}

    notice_flash "You have been authenticated via 2nd factor", "two_factor_auth"
    notice_flash "All 2nd factor authentication methods have been disabled", "two_factor_disable"

    error_flash "This account has not been setup for two factor authentication", 'two_factor_not_setup'
    error_flash "Already authenticated via 2nd factor", 'two_factor_already_authenticated'
    error_flash "You need to authenticate via 2nd factor before continuing.", 'two_factor_need_authentication'
    error_flash "Unable to remove all 2nd factor authentication methods", "two_factor_disable"

    auth_value_method :two_factor_already_authenticated_error_status, 403
    auth_value_method :two_factor_need_authentication_error_status, 401
    auth_value_method :two_factor_not_setup_error_status, 403

    session_key :two_factor_setup_session_key, :two_factor_auth_setup
    session_key :two_factor_auth_redirect_session_key, :two_factor_auth_redirect

    auth_value_method :two_factor_setup_heading, "<h2>Setup Two Factor Authentication</h2>"
    auth_value_method :two_factor_remove_heading, "<h2>Remove Two Factor Authentication</h2>"
    auth_value_method :two_factor_disable_link_text, "Remove All 2nd Factor Authentication Methods"
    auth_value_method :two_factor_auth_return_to_requested_location?, false

    auth_cached_method :two_factor_auth_links
    auth_cached_method :two_factor_setup_links
    auth_cached_method :two_factor_remove_links

    auth_value_methods :two_factor_modifications_require_password?

    auth_methods(
      :two_factor_authenticated?,
      :two_factor_remove,
      :two_factor_remove_auth_failures,
      :two_factor_remove_session,
      :two_factor_update_session
    )

    route(:two_factor_manage) do |r|
      require_account
      before_two_factor_manage_route

      r.get do
        all_links = two_factor_setup_links + two_factor_remove_links
        if all_links.length == 1
          redirect all_links[0][1]
        end
        two_factor_manage_view
      end
    end

    route(:two_factor_auth) do |r|
      require_login
      require_account_session
      require_two_factor_setup
      require_two_factor_not_authenticated
      before_two_factor_auth_route

      r.get do
        if two_factor_auth_links.length == 1
          redirect two_factor_auth_links[0][1]
        end
        two_factor_auth_view
      end
    end

    route(:two_factor_disable) do |r|
      require_account
      require_two_factor_setup
      before_two_factor_disable_route

      r.get do
        two_factor_disable_view
      end

      r.post do
        if two_factor_password_match?(param(password_param))
          transaction do
            before_two_factor_disable
            two_factor_remove
            _two_factor_remove_all_from_session
            after_two_factor_disable
          end
          set_notice_flash two_factor_disable_notice_flash
          redirect two_factor_disable_redirect
        end

        set_response_error_status(invalid_password_error_status)
        set_field_error(password_param, invalid_password_message)
        set_error_flash two_factor_disable_error_flash
        two_factor_disable_view
      end
    end

    def two_factor_modifications_require_password?
      modifications_require_password?
    end

    def authenticated?
      # False if not authenticated via single factor
      return false unless super

      # True if already authenticated via 2nd factor
      return true if two_factor_authenticated?

      # True if authenticated via single factor and 2nd factor not setup 
      !two_factor_authentication_setup?
    end

    def require_authentication
      super

      # Avoid database query if already authenticated via 2nd factor
      return if two_factor_authenticated?

      require_two_factor_authenticated if two_factor_authentication_setup?
    end

    def require_two_factor_setup
      # Avoid database query if already authenticated via 2nd factor
      return if two_factor_authenticated?

      return if uses_two_factor_authentication?

      set_redirect_error_status(two_factor_not_setup_error_status)
      set_redirect_error_flash two_factor_not_setup_error_flash
      redirect two_factor_need_setup_redirect
    end
    
    def require_two_factor_not_authenticated(auth_type = nil)
      if two_factor_authenticated? || (auth_type && two_factor_login_type_match?(auth_type))
        set_redirect_error_status(two_factor_already_authenticated_error_status)
        set_redirect_error_flash two_factor_already_authenticated_error_flash
        redirect two_factor_already_authenticated_redirect
      end
    end

    def require_two_factor_authenticated
      unless two_factor_authenticated?
        if two_factor_auth_return_to_requested_location?
          set_session_value(two_factor_auth_redirect_session_key, request.fullpath)
        end
        set_redirect_error_status(two_factor_need_authentication_error_status)
        set_redirect_error_flash two_factor_need_authentication_error_flash
        redirect two_factor_auth_required_redirect
      end
    end

    def two_factor_remove_auth_failures
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
      authenticated_by && authenticated_by.length >= 2
    end

    def two_factor_authentication_setup?
      possible_authentication_methods.length >= 2
    end

    def uses_two_factor_authentication?
      return false unless logged_in?
      set_session_value(two_factor_setup_session_key, two_factor_authentication_setup?) unless session.has_key?(two_factor_setup_session_key)
      session[two_factor_setup_session_key]
    end

    def two_factor_login_type_match?(type)
      authenticated_by && authenticated_by.include?(type)
    end

    def two_factor_remove
      nil
    end

    private

    def _two_factor_auth_links
      (super if defined?(super)) || []
    end

    def _two_factor_setup_links
      (super if defined?(super)) || []
    end

    def _two_factor_remove_links
      (super if defined?(super)) || []
    end

    def _two_factor_remove_all_from_session
      nil
    end

    def after_close_account
      super if defined?(super)
      two_factor_remove
    end

    def two_factor_authenticate(type)
      two_factor_update_session(type)
      two_factor_remove_auth_failures
      after_two_factor_authentication
      set_notice_flash two_factor_auth_notice_flash
      redirect_two_factor_authenticated
    end

    def redirect_two_factor_authenticated
      saved_two_factor_auth_redirect = remove_session_value(two_factor_auth_redirect_session_key)
      redirect saved_two_factor_auth_redirect || two_factor_auth_redirect
    end

    def two_factor_remove_session(type)
      authenticated_by.delete(type)
      remove_session_value(two_factor_setup_session_key)
      if authenticated_by.empty?
        clear_session
      end
    end

    def two_factor_update_session(auth_type)
      authenticated_by << auth_type
      set_session_value(two_factor_setup_session_key, true)
    end
  end
end
