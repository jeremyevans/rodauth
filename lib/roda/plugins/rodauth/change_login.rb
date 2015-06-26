class Roda
  module RodaPlugins
    module Rodauth
      ChangeLogin = Feature.define(:change_login)
      ChangeLogin.module_eval do
        route 'change-login'
        auth_value_methods :change_login_redirect

        get_block do |r|
          rodauth.view('change-login', 'Change Login')
        end

        post_block do |r|
          auth = rodauth

          if r[auth.login_param] == r[auth.login_confirm_param]
            if auth.account_from_session
              if auth.change_login(r[auth.login_param].to_s)
                r.redirect(auth.change_login_redirect)
              else
                @login_error = auth.login_errors_message
              end
            end
          else
            @login_error = auth.logins_do_not_match_message
          end

          auth.view('change-login', 'Change Login')
        end

        def change_login(login)
          account.set(login_column=>login).save(:raise_on_failure=>false)
        end

        def change_login_redirect
          "/"
        end
      end
    end
  end
end


