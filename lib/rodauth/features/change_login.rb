module Rodauth
  ChangeLogin = Feature.define(:change_login) do
    route 'change-login'
    notice_flash 'Your login has been changed'
    error_flash 'There was an error changing your login'
    view 'change-login', 'Change Login'
    after
    before
    additional_form_tags
    button 'Change Login'
    redirect
    require_account

    auth_value_methods :change_login_requires_password?

    auth_methods :change_login

    get_block do
      view('change-login', 'Change Login')
    end

    post_block do
      catch_error do
        if change_login_requires_password? && !password_match?(param(password_param))
          throw_error(:password, invalid_password_message)
        end

        login = param(login_param)
        unless login_meets_requirements?(login)
          throw_error(:login, login_does_not_meet_requirements_message)
        end

        unless login == param(login_confirm_param)
          throw_error(:login, logins_do_not_match_message)
        end

        transaction do
          before_change_login
          unless change_login(login)
            throw_error(:login, login_does_not_meet_requirements_message)
          end

          after_change_login
          set_notice_flash change_login_notice_flash
          redirect change_login_redirect
        end
      end

      set_error_flash change_login_error_flash
      change_login_view
    end

    def change_login_requires_password?
      modifications_require_password?
    end

    def change_login(login)
      updated = nil
      raised = raises_uniqueness_violation?{updated = account_ds.update(login_column=>login) == 1}
      if raised
        @login_requirement_message = 'already an account with this login'
      end
      updated && !raised
    end
  end
end
