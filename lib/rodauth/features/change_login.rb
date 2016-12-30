# frozen-string-literal: true

module Rodauth
  ChangeLogin = Feature.define(:change_login) do
    depends :login_password_requirements_base

    notice_flash 'Your login has been changed'
    error_flash 'There was an error changing your login'
    view 'change-login', 'Change Login'
    after
    before
    additional_form_tags
    button 'Change Login'
    redirect

    auth_value_methods :change_login_requires_password?

    auth_methods :change_login

    route do |r|
      require_account
      before_change_login_route

      r.get do
        change_login_view
      end

      r.post do
        catch_error do
          if change_login_requires_password? && !password_match?(param(password_param))
            throw_error_status(invalid_password_error_status, password_param, invalid_password_message)
          end

          login = param(login_param)
          unless login_meets_requirements?(login)
            throw_error_status(invalid_field_error_status, login_param, login_does_not_meet_requirements_message)
          end

          if require_login_confirmation? && login != param(login_confirm_param)
            throw_error_status(unmatched_field_error_status, login_param, logins_do_not_match_message)
          end

          transaction do
            before_change_login
            unless change_login(login)
              throw_error_status(invalid_field_error_status, login_param, login_does_not_meet_requirements_message)
            end

            after_change_login
            set_notice_flash change_login_notice_flash
            redirect change_login_redirect
          end
        end

        set_error_flash change_login_error_flash
        change_login_view
      end
    end

    def change_login_requires_password?
      modifications_require_password?
    end

    def change_login(login)
      updated = nil
      if account_ds.get(login_column).downcase == login.downcase
        @login_requirement_message = 'same as current login'
        return false
      end
      raised = raises_uniqueness_violation?{updated = update_account({login_column=>login}, account_ds.exclude(login_column=>login)) == 1}
      if raised
        @login_requirement_message = 'already an account with this login'
      end
      updated && !raised
    end
  end
end
