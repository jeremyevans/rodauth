module Rodauth
  ChangeLogin = Feature.define(:change_login) do
    route 'change-login'
    notice_flash 'Your login has been changed'
    error_flash 'There was an error changing your login'
    view 'change-login', 'Change Login'
    after
    additional_form_tags
    button 'Change Login'
    redirect
    require_account

    auth_value_method :change_login_requires_password?, true

    auth_methods :change_login

    get_block do |r, auth|
      auth.view('change-login', 'Change Login')
    end

    post_block do |r, auth|
      auth.catch_error do
        if auth.change_login_requires_password? && !auth.password_match?(auth.param(auth.password_param))
          auth.throw_error{@password_error = auth.invalid_password_message}
        end

        login = auth.param(auth.login_param)
        unless auth.login_meets_requirements?(login)
          auth.throw_error{@login_error = auth.login_does_not_meet_requirements_message}
        end

        unless login == auth.param(auth.login_confirm_param)
          auth.throw_error{@login_error = auth.logins_do_not_match_message}
        end

        auth.transaction do
          unless auth.change_login(login)
            auth.throw_error{@login_error = auth.login_does_not_meet_requirements_message}
          end

          auth.after_change_login
          auth.set_notice_flash auth.change_login_notice_flash
          r.redirect(auth.change_login_redirect)
        end
      end

      auth.set_error_flash auth.change_login_error_flash
      auth.change_login_view
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
