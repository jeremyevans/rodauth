module Rodauth
  CloseAccount = Feature.define(:close_account) do
    route 'close-account'
    notice_flash 'Your account has been closed'
    error_flash 'There was an error closing your account'
    view 'close-account', 'Close Account'
    additional_form_tags
    button 'Close Account'
    after
    redirect
    require_account

    auth_value_method :account_closed_status_value, 3
    auth_value_method :close_account_requires_password?, true

    auth_value_methods(
      :delete_account_on_close?
    )

    auth_methods(
      :close_account,
      :delete_account
    )

    get_block do |r, auth|
      auth.close_account_view
    end

    post_block do |r, auth|
      if !auth.close_account_requires_password? || auth.password_match?(auth.param(auth.password_param))
        auth.transaction do
          auth.close_account
          auth._after_close_account
          if auth.delete_account_on_close?
            auth.delete_account
          end
        end
        auth.clear_session

        auth.set_notice_flash auth.close_account_notice_flash
        r.redirect(auth.close_account_redirect)
      else
        @password_error = auth.invalid_password_message
        auth.set_error_flash auth.close_account_error_flash
        auth.close_account_view
      end
    end

    def close_account
      unless skip_status_checks?
        account_ds.update(account_status_id=>account_closed_status_value)
      end

      unless account_password_hash_column
        db[password_hash_table].where(account_id=>account_id_value).delete
      end
    end

    def delete_account
      account_ds.delete
    end

    def delete_account_on_close?
      skip_status_checks?
    end
  end
end
