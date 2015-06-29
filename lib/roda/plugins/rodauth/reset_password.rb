class Roda
  module RodaPlugins
    module Rodauth
      ResetPassword = Feature.define(:reset_password) do
        route 'reset-password'
        notice_flash "Your password has been reset"
        error_flash "There was an error resetting your password"
        redirect

        auth_value_methods(
          :no_matching_reset_password_key_message,
          :reset_password_email_sent_notice_message,
          :reset_password_email_sent_redirect,
          :reset_password_email_subject,
          :reset_password_id_column,
          :reset_password_key_column,
          :reset_password_key_param,
          :reset_password_key_value,
          :reset_password_table
        )
        auth_methods(
          :create_reset_password_key,
          :reset_password_autologin,
          :reset_password_email_body,
          :send_reset_password_email
        )

        get_block do |r|
          auth = rodauth
          if key = r[auth.reset_password_key_param]
            if auth.account_from_reset_password_key(key)
              auth.view('reset-password', 'Reset Password')
            else
              auth.set_redirect_error_flash auth.no_matching_reset_password_key_message
              r.redirect auth.login_redirect
            end
          end
        end

        post_block do |r|
          auth = rodauth
          if login = r[auth.login_param]
            if auth.account_from_login(login.to_s)
              key = auth.create_reset_password_key
              auth.send_reset_password_email
              auth.set_notice_flash auth.reset_password_email_sent_notice_message
              r.redirect auth.reset_password_email_sent_redirect
            else
              auth.set_redirect_error_flash auth.no_matching_login_message
              r.redirect auth.login_redirect
            end
          elsif key = r[auth.reset_password_key_param]
            if auth.account_from_reset_password_key(key)
              if r[auth.password_param] == r[auth.password_confirm_param]
                if auth.password_meets_requirements?(r[auth.password_param].to_s)
                  auth.set_password(r[auth.password_param])
                  if auth.reset_password_autologin?
                    auth.update_session
                  end
                  auth.set_notice_flash auth.reset_password_notice_flash
                  r.redirect(auth.reset_password_redirect)
                else
                  @password_error = auth.password_does_not_meet_requirements_message
                end
              else
                @password_error = auth.passwords_do_not_match_message
              end
              auth.set_error_flash auth.reset_password_error_flash
              auth.view('reset-password', 'Reset Password')
            else
              auth.set_redirect_error_flash auth.no_matching_reset_password_key_message
              r.redirect auth.login_redirect
            end
          end
        end

        def create_reset_password_key
          id = account.send(account_id)
          id_column = reset_password_id_column
          ds = account_model.db[reset_password_table].where(id_column=>id)
          @reset_password_key_value = key = random_key
          transaction do
            ds.where{deadline < Sequel::CURRENT_TIMESTAMP}.delete
            if ds.empty?
              ds.insert(id_column=>id, reset_password_key_column=>key)
            end
          end
          key
        end

        def reset_password_email_sent_notice_message
          "An email has been sent with a link to reset the password for your account"
        end

        def no_matching_reset_password_key_message
          "invalid password reset key"
        end

        def account_from_reset_password_key(key)
          id, key = key.split('_', 2)
          id_column = reset_password_id_column
          ds = account_model.db[reset_password_table].
            select(id_column).
            where(id_column=>id, reset_password_key_column=>key)
          @account = account_model.where(account_id=>ds).first
        end
        
        def reset_password_email_sent_redirect
          default_redirect
        end

        def reset_password_table
          :account_password_reset_keys
        end

        def reset_password_id_column
          :id
        end

        def reset_password_key_column
          :key
        end

        attr_reader :reset_password_key_value

        def send_reset_password_email
          send_email(reset_password_email_subject, reset_password_email_body)
        end

        def reset_password_email_body
          render('reset-password-email')
        end

        def reset_password_email_subject
          'Reset Password'
        end

        def reset_password_key_param
          'key'
        end

        def reset_password_autologin?
          false
        end

        def allow_reset_password?
          true
        end
      end
    end
  end
end
