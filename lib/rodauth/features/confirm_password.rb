# frozen-string-literal: true

module Rodauth
  ConfirmPassword = Feature.define(:confirm_password) do
    notice_flash "Your password has been confirmed"
    error_flash "There was an error confirming your password"
    view 'confirm-password', 'Confirm Password'
    additional_form_tags
    button 'Confirm Password'
    before
    after

    auth_value_methods :confirm_password_redirect

    auth_methods :confirm_password

    route do
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
      session.delete(:confirm_password_redirect) || default_redirect
    end
  end
end

