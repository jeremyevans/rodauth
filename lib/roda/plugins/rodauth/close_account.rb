class Roda
  module RodaPlugins
    module Rodauth
      CloseAccount = Feature.define(:close_account) do
        route 'close-account'
        notice_flash 'Your account has been closed'
        view 'close-account', 'Close Account'
        after
        additional_form_tags
        button 'Close Account'
        redirect
        require_login

        auth_value_methods :account_closed_status_value
        auth_methods :close_account

        get_block do |r, auth|
          auth.close_account_view
        end

        post_block do |r, auth|
          if auth._account_from_session
            auth.close_account
            auth.after_close_account
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
