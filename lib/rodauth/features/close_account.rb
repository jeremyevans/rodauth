module Rodauth
  CloseAccount = Feature.define(:close_account) do
    route 'close-account'
    notice_flash 'Your account has been closed'
    view 'close-account', 'Close Account'
    additional_form_tags
    button 'Close Account'
    redirect
    require_account
    auth_value_method :account_closed_status_value, 3

    auth_methods :close_account

    get_block do |r, auth|
      auth.close_account_view
    end

    post_block do |r, auth|
      auth.transaction do
        auth.close_account
        auth.after_close_account
      end
      auth.clear_session

      auth.set_notice_flash auth.close_account_notice_flash
      r.redirect(auth.close_account_redirect)
    end

    def close_account
      account.update(account_status_id=>account_closed_status_value)
      account.db[password_hash_table].where(account_id=>account_id_value).delete
    end
  end
end
