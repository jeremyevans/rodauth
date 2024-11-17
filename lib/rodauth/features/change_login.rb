# frozen-string-literal: true

module Rodauth
  Feature.define(:change_login, :ChangeLogin) do
    depends :login_password_requirements_base

    notice_flash 'Your login has been changed'
    error_flash 'There was an error changing your login'
    translatable_method :same_as_current_login_message, 'same as current login'
    loaded_templates %w'change-login login-field login-confirm-field password-field'
    view 'change-login', 'Change Login'
    after
    before
    additional_form_tags
    button 'Change Login'
    redirect
    response

    auth_value_methods :change_login_requires_password?

    auth_methods :change_login

    internal_request_method

    route do |r|
      require_account
      before_change_login_route

      r.get do
        change_login_view
      end

      r.post do
        catch_error do
          if change_login_requires_password? && !password_match?(param(password_param))
            throw_error_reason(:invalid_password, invalid_password_error_status, password_param, invalid_password_message)
          end

          login = login_param_value
          unless login_meets_requirements?(login)
            throw_error_status(invalid_field_error_status, login_param, login_does_not_meet_requirements_message)
          end

          if require_login_confirmation? && !login_confirmation_matches?(login, param(login_confirm_param))
            throw_error_reason(:logins_do_not_match, unmatched_field_error_status, login_param, logins_do_not_match_message)
          end

          transaction do
            before_change_login
            unless change_login(login)
              throw_error_status(invalid_field_error_status, login_param, login_does_not_meet_requirements_message)
            end

            after_change_login
          end
          change_login_response
        end

        set_error_flash change_login_error_flash
        change_login_view
      end
    end

    def change_login_requires_password?
      modifications_require_password?
    end

    def change_login(login)
      if account_ds.get(login_column).downcase == login.downcase
        set_login_requirement_error_message(:same_as_current_login, same_as_current_login_message)
        return false
      end

      update_login(login)
    end

    private

    def update_login(login)
      _update_login(login)
    end

    def _update_login(login)
      updated = nil
      raised = raises_uniqueness_violation?{updated = update_account({login_column=>login}, account_ds.exclude(login_column=>login)) == 1}
      if raised
        set_login_requirement_error_message(:already_an_account_with_this_login, already_an_account_with_this_login_message)
      end
      updated && !raised
    end
  end
end
