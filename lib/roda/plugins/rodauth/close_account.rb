class Roda
  module RodaPlugins
    module Rodauth
      CloseAccount = Feature.define(:close_account)
      CloseAccount.module_eval do
        auth_block_methods :close_account_post
        auth_value_methods :close_account_route, :close_account_redirect, :account_closed_status_value
        auth_methods :close_account
        auth_wrapper_methods :close_account

        CloseAccount::BLOCK = proc do |r|
          auth = rodauth
          r.is auth.close_account_route do
            r.get do
              auth.view('close-account', 'Close Account')
            end

            r.post do
              instance_exec(r, &auth.close_account_post_block)
            end
          end
        end

        def close_account_route_block
          CloseAccount::BLOCK
        end

        CloseAccount::POST = proc do |r|
          auth = rodauth

          if account = auth.wrap(auth.account_from_session)
            account.close_account
          end
          auth.clear_session

          r.redirect(auth.close_account_redirect)
        end

        def close_account_post_block
          CloseAccount::POST
        end

        def account_closed_status_value
          3
        end

        def close_account(account)
          account.update(account_status_id=>account_closed_status_value)
        end

        def close_account_route
          'close-account'
        end

        def close_account_redirect
          "/"
        end
      end
    end
  end
end


