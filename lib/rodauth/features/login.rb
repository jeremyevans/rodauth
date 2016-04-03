module Rodauth
  Login = Feature.define(:login) do
    route 'login'
    notice_flash "You have been logged in"
    error_flash "There was an error logging in"
    view 'login', 'Login'
    after
    after 'login_failure'
    before 'login_attempt'
    additional_form_tags
    button 'Login'
    redirect

    auth_value_method :login_form_footer, ''

    get_block do |r, auth|
      auth.login_view
    end

    post_block do |r, auth|
      auth.clear_session

      auth.catch_error do
        unless auth._account_from_login(auth.param(auth.login_param))
          auth.throw_error{@login_error = auth.no_matching_login_message}
        end

        auth._before_login_attempt

        unless auth.open_account?
          auth.throw_error{@login_error = auth.unverified_account_message}
        end

        unless auth.password_match?(auth.param(auth.password_param))
          auth._after_login_failure
          auth.throw_error{@password_error = auth.invalid_password_message}
        end

        auth.update_session
        auth._after_login
        auth.set_notice_flash auth.login_notice_flash
        r.redirect auth.login_redirect
      end

      auth.set_error_flash auth.login_error_flash
      auth.login_view
    end
  end
end
