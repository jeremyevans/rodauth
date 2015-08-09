class Roda
  module RodaPlugins
    module Rodauth
      CreateAccount = Feature.define(:create_account) do
        route 'create-account'
        error_flash "There was an error creating your account"
        view 'create-account', 'Create Account'
        after
        button 'Create Account'
        additional_form_tags
        redirect

        auth_value_methods :create_account_autologin?, :create_account_link, :create_account_notice_flash
        auth_methods :new_account, :save_account

        get_block do |r, auth|
          auth.create_account_view
        end

        post_block do |r, auth|
          login = r[auth.login_param].to_s
          password = r[auth.password_param].to_s
          if auth.verify_created_accounts? && auth._account_from_login(login)
            auth.set_error_flash auth.attempt_to_create_unverified_account_notice_message
            next auth.resend_verify_account_view
          elsif login == r[auth.login_confirm_param]
            if password == r[auth.password_confirm_param]
              if auth.password_meets_requirements?(password)
                auth._new_account(login)
                auth.transaction do
                  if auth.save_account
                    auth.set_password(password) unless auth.account_password_hash_column
                    auth.after_create_account
                    if auth.verify_created_accounts?
                      auth.generate_verify_account_key_value
                      auth.create_verify_account_key
                      auth.send_verify_account_email
                    elsif auth.create_account_autologin?
                      auth.update_session
                    end
                    auth.set_notice_flash auth.create_account_notice_flash
                    r.redirect(auth.create_account_redirect)
                  else
                    @login_error = auth.login_errors_message
                  end
                end
              else
                @password_error = auth.password_does_not_meet_requirements_message
              end
            else
              @password_error = auth.passwords_do_not_match_message
            end
          else
            @login_error = auth.logins_do_not_match_message
          end

          auth.set_error_flash auth.create_account_error_flash
          auth.create_account_view
        end

        def create_account_notice_flash
          if verify_created_accounts?
            verify_account_email_sent_notice_message
          else
            "Your account has been created"
          end
        end

        def create_account_link
          "<p><a href=\"#{prefix}/#{create_account_route}\">Create a New Account</a></p>"
        end

        def allow_creating_accounts?
          true
        end

        def create_account_autologin?
          false
        end

        def new_account(login)
          @account = account_model.new(login_column=>login)
          if account_password_hash_column
            account.set(account_password_hash_column=>password_hash(request[password_param].to_s))
          end
          unless skip_status_checks?
            account.set(account_status_id=>verify_created_accounts? ? account_unverified_status_value : account_open_status_value)
          end
          @account
        end
        
        def _new_account(login)
          @account = new_account(login)
        end

        def save_account
          account.save(:raise_on_failure=>false)
        end
      end
    end
  end
end
