class Roda
  module RodaPlugins
    module Rodauth
      ChangePassword = Feature.define(:change_password) do
        route 'change-password'
        notice_flash 'Your password has been changed'
        error_flash 'There was an error changing your password'
        add_redirect

        get_block do |r|
          rodauth.view('change-password', 'Change Password')
        end

        post_block do |r|
          auth = rodauth

          if r[auth.password_param] == r[auth.password_confirm_param]
            if auth.account_from_session
              auth.set_password(r[auth.password_param])
            end
            auth.set_notice_flash auth.change_password_notice_flash
            r.redirect(auth.change_password_redirect)
          end

          @password_error = auth.passwords_do_not_match_message
          auth.set_error_flash auth.change_password_error_flash
          auth.view('change-password', 'Change Password')
        end
      end
    end
  end
end

