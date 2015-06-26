require 'bcrypt'

class Roda
  module RodaPlugins
    module Rodauth
      CreateAccount = Feature.define(:create_account)
      CreateAccount.module_eval do
        route 'create-account'
        auth_value_methods :create_account_redirect
        auth_methods :new_account

        get_block do |r|
          rodauth.view('create-account', 'Create Account')
        end

        post_block do |r|
          auth = rodauth

          if r[auth.password_param] == r[auth.password_confirm_param]
            auth.new_account(r[auth.login_param])
            auth.transaction do
              if auth.save_account
                auth.set_password(r[auth.password_param])
                r.redirect(auth.create_account_redirect)
              else
                @login_error = auth.login_errors_message
              end
            end
          else
            @password_error = auth.passwords_do_not_match_message
          end

          auth.view('create-account', 'Create Account')
        end

        def login_errors_message
          if errors = account.errors.on(login_column)
            errors.join(', ')
          end
        end

        def passwords_do_not_match_message
          'passwords do not match'
        end

        def new_account(login)
          @account = account_model.new(login_column=>login)
          unless verify_created_accounts?
            account.set(account_status_id=>account_open_status_value)
          end
        end

        def save_account
          account.save(:raise_on_failure=>false)
        end

        def create_account_redirect
          "/"
        end
      end
    end
  end
end
