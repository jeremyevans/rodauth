require 'bcrypt'

class Roda
  module RodaPlugins
    module Rodauth
      CreateAccount = Feature.define(:create_account)
      CreateAccount.module_eval do
        auth_block_methods :create_account_post
        auth_value_methods :create_account_route, :create_account_redirect
        auth_methods :new_account
        auth_wrapper_methods :save_account, :login_errors_message

        CreateAccount::BLOCK = proc do |r|
          auth = rodauth
          r.is auth.create_account_route do
            r.get do
              auth.view('create-account', 'Create Account')
            end

            r.post do
              instance_exec(r, &auth.create_account_post_block)
            end
          end
        end

        def create_account_route_block
          CreateAccount::BLOCK
        end

        CreateAccount::POST = proc do |r|
          auth = rodauth

          if r[auth.password_param] == r[auth.password_confirm_param]
            account = auth.wrap(auth.new_account(r[auth.login_param]))
            auth.transaction do
              if account.save_account
                account.set_password(r[auth.password_param])
                r.redirect(auth.create_account_redirect)
              else
                @login_error = account.login_errors_message
              end
            end
          else
            @password_error = auth.passwords_do_not_match_message
          end

          auth.view('create-account', 'Create Account')
        end

        def create_account_post_block
          CreateAccount::POST
        end

        def login_errors_message(account)
          if errors = account.errors.on(login_column)
            errors.join(', ')
          end
        end

        def passwords_do_not_match_message
          'passwords do not match'
        end

        def new_account(login)
          account = account_model.new(login_column=>login)
          unless verify_created_accounts?
            account.set(account_status_id=>account_open_status_value)
          end
        end

        def save_account(account)
          account.save(:raise_on_failure=>false)
        end

        def create_account_route
          'create-account'
        end

        def create_account_redirect
          "/"
        end
      end
    end
  end
end
