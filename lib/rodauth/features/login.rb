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

      if auth._account_from_login(auth.param(auth.login_param))
        auth._before_login_attempt

        if auth.open_account?
          if auth.password_match?(auth.param(auth.password_param))
            auth.update_session
            auth._after_login
            auth.set_notice_flash auth.login_notice_flash
            r.redirect auth.login_redirect
          else
            auth._after_login_failure
            @password_error = auth.invalid_password_message
          end
        else
          @login_error = auth.unverified_account_message
        end
      else
        @login_error = auth.no_matching_login_message
      end

      auth.set_error_flash auth.login_error_flash
      auth.login_view
    end
  end
end
