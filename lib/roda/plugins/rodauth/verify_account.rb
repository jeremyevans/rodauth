class Roda
  module RodaPlugins
    module Rodauth
      VerifyAccount = Feature.define(:verify_account) do
        route 'verify-account'
        notice_flash "Your account has been verified"
        view 'verify-account', 'Verify Account'
        additional_form_tags
        after
        redirect

        auth_value_methods(
          :no_matching_verify_account_key_message,
          :verify_account_email_subject,
          :verify_account_id_column,
          :verify_account_key_column,
          :verify_account_key_param,
          :verify_account_key_value,
          :verify_account_table
        )
        auth_methods(
          :create_verify_account_key,
          :send_verify_account_email,
          :verify_account,
          :verify_account_autologin,
          :verify_account_email_body
        )

        get_block do |r, auth|
          if key = r[auth.verify_account_key_param]
            if auth._account_from_verify_account_key(key)
              auth.verify_account_view
            else
              auth.set_redirect_error_flash auth.no_matching_verify_account_key_message
              r.redirect auth.login_redirect
            end
          end
        end

        post_block do |r, auth|
          if key = r[auth.verify_account_key_param]
            if auth._account_from_verify_account_key(key)
              auth.verify_account
              auth.after_verify_account
              if auth.create_account_autologin?
                auth.update_session
              end
              auth.set_notice_flash auth.verify_account_notice_flash
              r.redirect(auth.verify_account_redirect)
            else
              auth.set_redirect_error_flash auth.no_matching_verify_account_key_message
              r.redirect auth.login_redirect
            end
          end
        end

        def generate_verify_account_key_value
          @verify_account_key_value = random_key
        end

        def create_verify_account_key
          id = account.send(account_id)
          id_column = verify_account_id_column
          ds = account_model.db[verify_account_table].where(id_column=>id)
          transaction do
            ds.where{deadline < Sequel::CURRENT_TIMESTAMP}.delete
            if ds.empty?
              ds.insert(id_column=>id, verify_account_key_column=>verify_account_key_value)
            end
          end
        end

        def verify_account
          account.set(account_status_id=>account_open_status_value).save(:raise_on_failure=>true)
        end

        def reset_password_email_sent_notice_message
          "An email has been sent with a link to verify this account"
        end

        def no_matching_reset_password_key_message
          "invalid verify account key"
        end

        def _account_from_verify_account_key(key)
          @account = account_from_verify_account_key(key)
        end

        def account_from_verify_account_key(key)
          id, key = key.split('_', 2)
          id_column = verify_account_id_column
          ds = account_model.db[verify_account_table].
            select(id_column).
            where(id_column=>id, verify_account_key_column=>key)
          @account = account_model.where(account_status_id=>account_unverified_status_value, account_id=>ds).first
        end
        
        def verify_account_email_sent_redirect
          default_redirect
        end

        def verify_account_table
          :account_verification_keys
        end

        def verify_account_id_column
          :id
        end

        def verify_account_key_column
          :key
        end

        attr_reader :verify_account_key_value

        def send_verify_account_email
          send_email(verify_account_email_subject, verify_account_email_body)
        end

        def verify_account_email_body
          render('verify-account-email')
        end

        def verify_account_email_subject
          'Verify Account'
        end

        def verify_account_key_param
          'key'
        end

        def verify_account_autologin?
          false
        end

        def verify_created_accounts?
          true
        end
      end
    end
  end
end

