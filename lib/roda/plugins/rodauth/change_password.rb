class Roda
  module RodaPlugins
    module Rodauth
      ChangePassword = Feature.define(:change_password)
      ChangePassword.module_eval do
        route 'change-password'
        auth_value_methods :change_password_redirect

        get_block do |r|
          rodauth.view('change-password', 'Change Password')
        end

        post_block do |r|
          auth = rodauth

          if r[auth.password_param] == r[auth.password_confirm_param]
            if auth.account_from_session
              auth.set_password(r[auth.password_param])
            end
            r.redirect(auth.change_password_redirect)
          end

          @password_error = auth.passwords_do_not_match_message
          auth.view('change-password', 'Change Password')
        end

        def change_password_redirect
          "/"
        end
      end
    end
  end
end

