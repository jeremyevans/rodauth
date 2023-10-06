# frozen-string-literal: true

module Rodauth
  Feature.define(:change_password, :ChangePassword) do
    depends :login_password_requirements_base

    notice_flash 'Your password has been changed'
    error_flash 'There was an error changing your password'
    loaded_templates %w'change-password password-field password-confirm-field'
    view 'change-password', 'Change Password'
    after
    before
    additional_form_tags
    button 'Change Password'
    redirect
    response

    translatable_method :new_password_label, 'New Password'
    auth_value_method :new_password_param, 'new-password'

    auth_value_methods(
      :change_password_requires_password?,
      :invalid_previous_password_message
    )

    internal_request_method

    route do |r|
      require_account
      before_change_password_route

      r.get do
        change_password_view
      end

      r.post do
        catch_error do
          if change_password_requires_password? && !password_match?(param(password_param))
            throw_error_reason(:invalid_previous_password, invalid_password_error_status, password_param, invalid_previous_password_message)
          end

          password = param(new_password_param)
          if require_password_confirmation? && password != param(password_confirm_param)
            throw_error_reason(:passwords_do_not_match, unmatched_field_error_status, new_password_param, passwords_do_not_match_message)
          end

          if password_match?(password) 
            throw_error_reason(:same_as_existing_password, invalid_field_error_status, new_password_param, same_as_existing_password_message)
          end

          unless password_meets_requirements?(password)
            throw_error_status(invalid_field_error_status, new_password_param, password_does_not_meet_requirements_message)
          end

          transaction do
            before_change_password
            set_password(password)
            after_change_password
          end
          change_password_response
        end

        set_error_flash change_password_error_flash
        change_password_view
      end
    end

    def change_password_requires_password?
      modifications_require_password?
    end

    def invalid_previous_password_message
      invalid_password_message
    end
  end
end
