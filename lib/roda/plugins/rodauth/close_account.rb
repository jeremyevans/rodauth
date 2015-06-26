class Roda
  module RodaPlugins
    module Rodauth
      CloseAccount = Feature.define(:close_account) do
        route 'close-account'
        notice_flash 'Your account has been closed'
        redirect
        auth_value_methods :account_closed_status_value
        auth_methods :close_account

        get_block do |r|
          rodauth.view('close-account', 'Close Account')
        end

        post_block do |r|
          auth = rodauth

          if auth.account_from_session
            auth.close_account
          end
          auth.clear_session

          auth.set_notice_flash auth.close_account_notice_flash
          r.redirect(auth.close_account_redirect)
        end

        def account_closed_status_value
          3
        end

        def close_account
          account.update(account_status_id=>account_closed_status_value)
          account.db[password_hash_table].where(account_id=>account.send(account_id)).delete
        end
      end
    end
  end
end
