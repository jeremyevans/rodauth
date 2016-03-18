module Rodauth
  Lockout = Feature.define(:lockout) do
    depends :login
    route 'unlock-account'
    view 'unlock-account-request', 'Request Account Unlock', 'unlock_account_request'
    view 'unlock-account', 'Unlock Account', 'unlock_account'

    auth_value_methods(
      :account_lockouts_id_column,
      :account_lockouts_deadline_column,
      :account_lockouts_deadline_interval,
      :account_lockouts_key_column,
      :account_lockouts_table,
      :account_login_failures_id_column,
      :account_login_failures_number_column,
      :account_login_failures_table,
      :max_invalid_logins,
      :unlock_account_additional_form_tags,
      :unlock_account_autologin?,
      :unlock_account_button,
      :unlock_account_email_subject,
      :unlock_account_key_param,
      :unlock_account_notice_flash,
      :unlock_account_redirect,
      :unlock_account_request_additional_form_tags,
      :unlock_account_request_button,
      :unlock_account_request_notice_flash,
      :unlock_account_request_redirect,
      :unlock_account_route
    )
    auth_methods(
      :after_unlock_account,
      :after_unlock_account_request,
      :clear_invalid_login_attempts,
      :create_unlock_account_email,
      :generate_unlock_account_key,
      :get_unlock_account_key,
      :invalid_login_attempted,
      :locked_out?,
      :send_unlock_account_email,
      :unlock_account_email_body,
      :unlock_account_email_link,
      :unlock_account,
      :unlock_account_key
    )

    get_block do |r, auth|
      if auth._account_from_unlock_key(r[auth.unlock_account_key_param].to_s)
        auth.unlock_account_view
      else
        auth.set_redirect_error_flash auth.no_matching_unlock_account_key_message
        r.redirect auth.require_login_redirect
      end
    end

    post_block do |r, auth|
      if login = r[auth.login_param]
        if auth._account_from_login(login.to_s)
          auth.transaction do
            auth.send_unlock_account_email
            auth.after_unlock_account_request
          end
          auth.set_notice_flash auth.unlock_account_request_notice_flash
          r.redirect auth.unlock_account_request_redirect
        end
      elsif key = r[auth.unlock_account_key_param]
        if auth._account_from_unlock_key(key.to_s)
          auth.unlock_account
          auth.after_unlock_account
          if auth.unlock_account_autologin?
            auth.update_session
          end
          auth.set_notice_flash auth.unlock_account_notice_flash
          r.redirect(auth.unlock_account_redirect)
        end
      end
    end

    def before_login_attempt
      super
      if locked_out?
        set_error_flash login_error_flash
        response.write unlock_account_request_view
        request.halt
      end
    end

    def after_login
      super
      clear_invalid_login_attempts
    end

    def after_login_failure
      super
      invalid_login_attempted
    end

    def after_unlock_account
    end

    def after_unlock_account_request
    end

    alias unlock_account_route lockout_route

    def unlock_account_autologin?
      false
    end

    def unlock_account_notice_flash
      "Your account has been unlocked"
    end

    def unlock_account_redirect
      default_redirect
    end

    def unlock_account_button
      'Unlock Account'
    end

    def unlock_account_additional_form_tags
    end

    def unlock_account_request_notice_flash
      "An email has been sent to you with a link to unlock your account"
    end

    def unlock_account_request_redirect
      default_redirect
    end

    def unlock_account_request_button
      'Request Account Unlock'
    end

    def unlock_account_request_additional_form_tags
    end

    # This is solely for bruteforce protection, so we allow 100 tries.
    def max_invalid_logins
      100
    end

    def account_login_failures_table
      :account_login_failures
    end

    def account_login_failures_id_column
      :id
    end

    def account_login_failures_number_column
      :number
    end

    def account_login_failures_dataset
      db[account_login_failures_table].where(account_login_failures_id_column=>account_id_value)
    end

    def account_lockouts_table
      :account_lockouts
    end

    def account_lockouts_id_column
      :id
    end

    def account_lockouts_key_column
      :key
    end

    def account_lockouts_deadline_column
      :deadline
    end

    def account_lockouts_dataset
      db[account_lockouts_table].where(account_lockouts_id_column=>account_id_value)
    end

    def locked_out?
      if lockout = account_lockouts_dataset.first
        t = lockout[account_lockouts_deadline_column]
        t = Time.parse(t) unless t.is_a?(Time)
        if Time.now < t
          true
        else
          unlock_account
          false
        end
      else
        false
      end
    end

    def unlock_account
      transaction do
        account_login_failures_dataset.delete
        account_lockouts_dataset.delete
      end
    end

    def no_matching_unlock_account_key_message
      'No matching unlock account key'
    end

    def clear_invalid_login_attempts
      unlock_account
    end

    def invalid_login_attempted
      ds = account_login_failures_dataset.
          where(account_login_failures_id_column=>account_id_value)

      number = if db.database_type == :postgres
        ds.returning(account_login_failures_number_column).
          with_sql(:update_sql, account_login_failures_number_column=>Sequel.expr(account_login_failures_number_column)+1).
          single_value
      else
        if ds.update(account_login_failures_number_column=>Sequel.expr(account_login_failures_number_column)+1) > 0
          ds.get(account_login_failures_number_column)
        end
      end

      unless number
        account_login_failures_dataset.insert(account_login_failures_id_column=>account_id_value)
        number = 1
      end

      if number >= max_invalid_logins
        @unlock_account_key_value = generate_unlock_account_key
        hash = {account_lockouts_id_column=>account_id_value, account_lockouts_key_column=>unlock_account_key_value}
        set_deadline_value(hash, account_lockouts_deadline_column, account_lockouts_deadline_interval)
        account_lockouts_dataset.insert(hash)
      end
    end

    def account_lockouts_deadline_interval
      {:days=>1}
    end

    def get_unlock_account_key
      account_lockouts_dataset.get(account_lockouts_key_column)
    end

    def generate_unlock_account_key
      random_key
    end

    attr_reader :unlock_account_key_value

    def _account_from_unlock_key(key)
      @account = account_from_unlock_key(key)
    end

    def account_from_unlock_key(key)
      id, key = key.split('_', 2)
      return unless id && key

      id_column = account_lockouts_id_column
      id = id.to_i

      return unless actual = db[account_lockouts_table].
        where(account_lockouts_id_column=>id).
        get(account_lockouts_key_column)

      return unless timing_safe_eql?(key, actual)

      account_model.where(account_id=>id).first
    end

    def unlock_account_key_param
      'key'
    end

    def create_unlock_account_email
      create_email(unlock_account_email_subject, unlock_account_email_body)
    end

    def send_unlock_account_email
      @unlock_account_key_value = get_unlock_account_key
      create_unlock_account_email.deliver!
    end

    def unlock_account_email_body
      render('unlock-account-email')
    end

    def unlock_account_email_link
      "#{request.base_url}#{prefix}/#{unlock_account_route}?#{unlock_account_key_param}=#{account_id_value}_#{unlock_account_key_value}"
    end

    def unlock_account_email_subject
      'Unlock Account'
    end

    def after_close_account
      super
      account_login_failures_dataset.delete
      account_lockouts_dataset.delete
    end

    def require_mail?
      true
    end

    def use_date_arithmetic?
      db.database_type == :mysql
    end
  end
end
