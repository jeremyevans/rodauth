class Roda
  module RodaPlugins
    module Rodauth
      Login = Feature.define(:login) do
        route 'login'
        notice_flash "You have been logged in"
        error_flash "There was an error logging in"
        view 'login', 'Login'
        after
        additional_form_tags
        button 'Login'
        redirect

        auth_value_methods :invalid_password_message, :login_form_footer
        auth_methods(
          :after_login_failure,
          :before_login_attempt,
          :password_match?
        )

        get_block do |r, auth|
          auth.login_view
        end

        post_block do |r, auth|
          auth.clear_session

          if auth._account_from_login(r[auth.login_param].to_s)
            auth.before_login_attempt

            if auth.open_account?
              if auth.password_match?(r[auth.password_param].to_s)
                auth.update_session
                auth.after_login
                auth.set_notice_flash auth.login_notice_flash
                r.redirect auth.login_redirect
              else
                auth.after_login_failure
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

        def before_login_attempt
        end

        def after_login_failure
        end

        def login_form_footer
          ""
        end

        def invalid_password_message
          "invalid password"
        end

        def password_match?(password)
          require 'bcrypt'
          if account_password_hash_column
            BCrypt::Password.new(account.send(account_password_hash_column)) == password
          else
            id = account.send(account_id)
            if salt = db.get{rodauth_get_salt(id)}
              hash = BCrypt::Engine.hash_secret(password, salt)
              db.get{rodauth_valid_password_hash(id, hash)}
            end
          end
        end
      end
    end
  end
end
