class Roda
  module RodaPlugins
    module Rodauth
      Login = Feature.define(:login) do
        route 'login'
        notice_flash "You have been logged in"
        error_flash "There was an error logging in"
        view 'login', 'Login'
        redirect
        auth_value_methods :invalid_password_message
        auth_methods :password_match?

        get_block do |r|
          rodauth.login_view
        end

        post_block do |r|
          auth = rodauth
          auth.clear_session

          if auth._account_from_login(r[auth.login_param].to_s)
            if auth.open_account?
              if auth.password_match?(r[auth.password_param].to_s)
                auth.update_session
                auth.set_notice_flash auth.login_notice_flash
                r.redirect auth.login_redirect
              else
                @password_error = auth.invalid_password_message
                if auth.allow_reset_password?
                  @reset_password_form = auth.render("reset-password-request")
                end
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

        def invalid_password_message
          "invalid password"
        end

        def password_match?(password)
          account_model.db.get{|db| db.account_valid_password(account.send(account_id), password)}
        end
      end
    end
  end
end
