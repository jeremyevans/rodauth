# frozen-string-literal: true

module Rodauth
  Feature.define(:confirm_password, :ConfirmPassword) do
    notice_flash "Your password has been confirmed"
    error_flash "There was an error confirming your password"
    error_flash "You need to confirm your password before continuing", 'password_authentication_required'
    loaded_templates %w'confirm-password password-field'
    view 'confirm-password', 'Confirm Password'
    additional_form_tags
    button 'Confirm Password'
    before
    after
    response
    redirect(:password_authentication_required){confirm_password_path}

    session_key :confirm_password_redirect_session_key, :confirm_password_redirect
    translatable_method :confirm_password_link_text, "Enter Password"
    auth_value_method :password_authentication_required_error_status, 401

    auth_value_methods :confirm_password_redirect

    auth_methods :confirm_password

    route do |r|
      require_login
      require_account_session
      before_confirm_password_route

      r.get do
        confirm_password_view
      end

      r.post do
        if password_match?(param(password_param))
          transaction do
            before_confirm_password
            confirm_password
            after_confirm_password
          end
          confirm_password_response
        else
          set_response_error_reason_status(:invalid_password, invalid_password_error_status)
          set_field_error(password_param, invalid_password_message)
          set_error_flash confirm_password_error_flash
          confirm_password_view
        end
      end
    end

    def require_password_authentication
      require_login

      if require_password_authentication? && has_password?
        set_redirect_error_status(password_authentication_required_error_status)
        set_error_reason :password_authentication_required
        set_redirect_error_flash password_authentication_required_error_flash
        set_session_value(confirm_password_redirect_session_key, request.fullpath)
        redirect password_authentication_required_redirect
      end
    end

    def confirm_password
      authenticated_by.delete('autologin')
      authenticated_by.delete('remember')
      authenticated_by.delete('email_auth')
      authenticated_by.delete('password')
      authenticated_by.unshift("password")
      remove_session_value(autologin_type_session_key)
      nil
    end

    def confirm_password_redirect
      remove_session_value(confirm_password_redirect_session_key) || default_redirect
    end

    private

    def _two_factor_auth_links
      links = (super if defined?(super)) || []
      if authenticated_by.length == 1 && !authenticated_by.include?('password') && has_password?
        links << [5, confirm_password_path, confirm_password_link_text]
      end
      links
    end

    def require_password_authentication?
      return true if defined?(super) && super
      !authenticated_by.include?('password')
    end
  end
end
