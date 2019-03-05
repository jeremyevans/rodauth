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
    auth_value_methods :confirm_password_redirect

    auth_methods :confirm_password

    route do |r|
      require_account
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
      nil
    end

    def confirm_password_redirect
      session.delete(confirm_password_redirect_session_key) || default_redirect
    end
  end
end

