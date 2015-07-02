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
        redirect

        auth_value_methods :invalid_password_message
        auth_methods :password_match?

        get_block do |r, auth|
          auth.login_view
        end

        post_block do |r, auth|
          auth.clear_session

          if auth._account_from_login(r[auth.login_param].to_s)
            if auth.open_account?
              if auth.password_match?(r[auth.password_param].to_s)
                auth.update_session
                auth.after_login
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
          if use_database_password_validation?
            account_model.db.get{|db| db.account_valid_password(account.send(account_id), password)}
          else
            require 'bcrypt'
            BCrypt::Password.new(account.send(account_password_hash_column)) == password
          end
        end

        private

        def use_database_password_validation?
          account_password_hash_column == nil
        end
      end
    end
  end
end
