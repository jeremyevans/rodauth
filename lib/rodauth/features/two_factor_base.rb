# frozen-string-literal: true

module Rodauth
  Feature.define(:two_factor_base, :TwoFactorBase) do
    loaded_templates %w'two-factor-manage two-factor-auth two-factor-disable'

    view 'two-factor-manage', 'Manage Multifactor Authentication', 'two_factor_manage'
    view 'two-factor-auth', 'Authenticate Using Additional Factor', 'two_factor_auth'
    view 'two-factor-disable', 'Remove All Multifactor Authentication Methods', 'two_factor_disable'

    before :two_factor_disable

    after :two_factor_authentication
    after :two_factor_disable

    additional_form_tags :two_factor_disable

    button "Remove All Multifactor Authentication Methods", :two_factor_disable

    redirect(:two_factor_auth)
    redirect(:two_factor_already_authenticated)
    redirect(:two_factor_disable)
    redirect(:two_factor_need_setup){two_factor_manage_path}
    redirect(:two_factor_auth_required){two_factor_auth_path}

    response :two_factor_disable

    notice_flash "You have been multifactor authenticated", "two_factor_auth"
    notice_flash "All multifactor authentication methods have been disabled", "two_factor_disable"

    error_flash "This account has not been setup for multifactor authentication", 'two_factor_not_setup'
    error_flash "You have already been multifactor authenticated", 'two_factor_already_authenticated'
    error_flash "You need to authenticate via an additional factor before continuing", 'two_factor_need_authentication'
    error_flash "Unable to remove all multifactor authentication methods", "two_factor_disable"

    auth_value_method :two_factor_already_authenticated_error_status, 403
    auth_value_method :two_factor_need_authentication_error_status, 401
    auth_value_method :two_factor_not_setup_error_status, 403

    session_key :two_factor_setup_session_key, :two_factor_auth_setup
    session_key :two_factor_auth_redirect_session_key, :two_factor_auth_redirect

    translatable_method :two_factor_setup_heading, "<h2>Setup Multifactor Authentication</h2>"
    translatable_method :two_factor_remove_heading, "<h2>Remove Multifactor Authentication</h2>"
    translatable_method :two_factor_disable_link_text, "Remove All Multifactor Authentication Methods"
    auth_value_method :two_factor_auth_return_to_requested_location?, false

    auth_value_methods :two_factor_modifications_require_password?

    auth_methods(
      :two_factor_authenticated?,
      :two_factor_remove,
      :two_factor_remove_auth_failures,
      :two_factor_remove_session,
      :two_factor_update_session
    )

    auth_private_methods(
      :two_factor_auth_links,
      :two_factor_auth_response,
      :two_factor_setup_links,
      :two_factor_remove_links
    )

    internal_request_method :two_factor_disable

    route(:two_factor_manage, 'multifactor-manage') do |r|
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

    route(:two_factor_auth, 'multifactor-auth') do |r|
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

    route(:two_factor_disable, 'multifactor-disable') do |r|
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
          two_factor_disable_response
        end

        set_response_error_reason_status(:invalid_password, invalid_password_error_status)
        set_field_error(password_param, invalid_password_message)
        set_error_flash two_factor_disable_error_flash
        two_factor_disable_view
      end
    end

    def two_factor_modifications_require_password?
      modifications_require_password?
    end

    def authenticated?
      super && !two_factor_partially_authenticated?
    end

    def require_authentication
      super
      require_two_factor_authenticated if two_factor_partially_authenticated?
    end

    def require_two_factor_setup
      # Avoid database query if already authenticated via 2nd factor
      return if two_factor_authenticated?

      return if uses_two_factor_authentication?

      set_redirect_error_status(two_factor_not_setup_error_status)
      set_error_reason :two_factor_not_setup
      set_redirect_error_flash two_factor_not_setup_error_flash
      redirect two_factor_need_setup_redirect
    end
    
    def require_two_factor_not_authenticated(auth_type = nil)
      if two_factor_authenticated? || (auth_type && two_factor_login_type_match?(auth_type))
        set_redirect_error_status(two_factor_already_authenticated_error_status)
        set_error_reason :two_factor_already_authenticated
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
        set_error_reason :two_factor_need_authentication
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

    def two_factor_partially_authenticated?
      logged_in? && !two_factor_authenticated? && uses_two_factor_authentication?
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

    def two_factor_auth_links
      @two_factor_auth_links ||= _filter_links(_two_factor_auth_links)
    end

    def two_factor_setup_links
      @two_factor_setup_links ||= _filter_links(_two_factor_setup_links)
    end

    def two_factor_remove_links
      @two_factor_remove_links ||= _filter_links(_two_factor_remove_links)
    end

    private

    def _two_factor_auth_links
      (super if defined?(super)) || []
    end

    def _two_factor_setup_links
      []
    end

    def _two_factor_remove_links
      []
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
      require_response(:_two_factor_auth_response)
    end

    def _two_factor_auth_response
      saved_two_factor_auth_redirect = remove_session_value(two_factor_auth_redirect_session_key)
      set_notice_flash two_factor_auth_notice_flash
      redirect(saved_two_factor_auth_redirect || two_factor_auth_redirect)
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
