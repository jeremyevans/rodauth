# frozen-string-literal: true

module Rodauth
  Feature.define(:confirm_password, :ConfirmPassword) do
    notice_flash "Your password has been confirmed"
    error_flash "There was an error confirming your password"
    loaded_templates %w'confirm-password password-field'
    view 'confirm-password', 'Confirm Password'
    additional_form_tags
    button 'Confirm Password'
    before
    after

    session_key :confirm_password_redirect_session_key, :confirm_password_redirect
    auth_value_method :confirm_password_link_text, "Enter Password"

    auth_value_methods :confirm_password_redirect

    auth_methods :confirm_password

    route do |r|
      require_login
      require_account_session
      before_confirm_password_route

      request.get do
        confirm_password_view
      end

      request.post do
        if password_match?(param(password_param))
          transaction do
            before_confirm_password
            confirm_password
            after_confirm_password
          end
          set_notice_flash confirm_password_notice_flash
          redirect confirm_password_redirect
        else
          set_response_error_status(invalid_password_error_status)
          set_field_error(password_param, invalid_password_message)
          set_error_flash confirm_password_error_flash
          confirm_password_view
        end
      end
    end

    def confirm_password
      authenticated_by.delete('autologin')
      authenticated_by.delete('remember')
      authenticated_by.delete('email_auth')
      authenticated_by.delete('password')
      authenticated_by.unshift("password")
      session.delete(autologin_type_session_key)
      nil
    end

    def confirm_password_redirect
      session.delete(confirm_password_redirect_session_key) || default_redirect
    end

    private

    def _two_factor_auth_links
      links = (super if defined?(super)) || []
      if authenticated_by.length == 1 && !authenticated_by.include?('password') && has_password?
        links << [5, confirm_password_path, confirm_password_link_text]
      end
      links
    end
  end
end

