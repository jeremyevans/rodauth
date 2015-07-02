class Roda
  module RodaPlugins
    module Rodauth
      ChangeLogin = Feature.define(:change_login) do
        route 'change-login'
        notice_flash 'Your login has been changed'
        error_flash 'There was an error changing your login'
        view 'change-login', 'Change Login'
        after
        additional_form_tags
        redirect
        require_login

        auth_methods :change_login

        get_block do |r, auth|
          auth.view('change-login', 'Change Login')
        end

        post_block do |r, auth|
          if r[auth.login_param] == r[auth.login_confirm_param]
            if auth._account_from_session
              if auth.change_login(r[auth.login_param].to_s)
                auth.after_change_login
                auth.set_notice_flash auth.change_login_notice_flash
                r.redirect(auth.change_login_redirect)
              else
                @login_error = auth.login_errors_message
              end
            end
          else
            @login_error = auth.logins_do_not_match_message
          end

          auth.set_error_flash auth.change_login_error_flash
          auth.change_login_view
        end

        def change_login(login)
          account.set(login_column=>login).save(:raise_on_failure=>false)
        end
      end
    end
  end
end


