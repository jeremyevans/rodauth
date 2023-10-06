# frozen-string-literal: true

module Rodauth
  Feature.define(:close_account, :CloseAccount) do
    notice_flash 'Your account has been closed'
    error_flash 'There was an error closing your account'
    loaded_templates %w'close-account password-field'
    view 'close-account', 'Close Account'
    additional_form_tags
    button 'Close Account'
    after
    before
    redirect
    response

    auth_value_method :account_closed_status_value, 3

    auth_value_methods(
      :close_account_requires_password?,
      :delete_account_on_close?
    )

    auth_methods(
      :close_account,
      :delete_account
    )

    internal_request_method

    route do |r|
      require_account
      before_close_account_route

      r.get do
        close_account_view
      end

      r.post do
        catch_error do
          if close_account_requires_password? && !password_match?(param(password_param))
            throw_error_reason(:invalid_password, invalid_password_error_status, password_param, invalid_password_message)
          end

          transaction do
            before_close_account
            close_account
            after_close_account
            if delete_account_on_close?
              delete_account
            end
          end
          clear_session

          close_account_response
        end

        set_error_flash close_account_error_flash
        close_account_view
      end
    end

    def close_account_requires_password?
      modifications_require_password?
    end

    def close_account
      unless skip_status_checks?
        update_account(account_status_column=>account_closed_status_value)
      end

      unless account_password_hash_column
        password_hash_ds.delete
      end
    end

    def delete_account
      account_ds.delete
    end

    def delete_account_on_close?
      skip_status_checks?
    end

    def skip_status_checks?
      false
    end
  end
end
