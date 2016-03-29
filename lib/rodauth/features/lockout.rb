module Rodauth
  Lockout = Feature.define(:lockout) do
    depends :login
    route 'unlock-account'
    view 'unlock-account-request', 'Request Account Unlock', 'unlock_account_request'
    view 'unlock-account', 'Unlock Account', 'unlock_account'
    after 'unlock_account'
    after 'unlock_account_request'
    additional_form_tags 'unlock_account'
    additional_form_tags 'unlock_account_request'
    button 'Unlock Account', 'unlock_account'
    button 'Request Account Unlock', 'unlock_account_request'
    error_flash "There was an error unlocking your account", 'unlock_account'
    notice_flash "Your account has been unlocked", 'unlock_account'
    notice_flash "An email has been sent to you with a link to unlock your account", 'unlock_account_request'
    redirect :unlock_account
    redirect :unlock_account_request
      
    auth_value_method :unlock_account_autologin?, true
    auth_value_method :max_invalid_logins, 100
    auth_value_method :account_login_failures_table, :account_login_failures
    auth_value_method :account_login_failures_id_column, :id
    auth_value_method :account_login_failures_number_column, :number
    auth_value_method :account_lockouts_table, :account_lockouts
    auth_value_method :account_lockouts_id_column, :id
    auth_value_method :account_lockouts_key_column, :key
    auth_value_method :account_lockouts_deadline_column, :deadline
    auth_value_method :account_lockouts_deadline_interval, {:days=>1}
    auth_value_method :unlock_account_email_subject, 'Unlock Account'
    auth_value_method :unlock_account_key_param, 'key'
    auth_value_method :unlock_account_requires_password?, false

    auth_value_methods(
      :unlock_account_redirect,
      :unlock_account_request_redirect,
      :unlock_account_route
    )
    auth_methods(
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
      if auth._account_from_unlock_key(auth.param(auth.unlock_account_key_param))
        auth.unlock_account_view
      else
        auth.set_redirect_error_flash auth.no_matching_unlock_account_key_message
        r.redirect auth.require_login_redirect
      end
    end

    post_block do |r, auth|
      if login = auth._param(auth.login_param)
        if auth._account_from_login(login)
          auth.transaction do
            auth.send_unlock_account_email
            auth._after_unlock_account_request
          end
          auth.set_notice_flash auth.unlock_account_request_notice_flash
          r.redirect auth.unlock_account_request_redirect
        end
      elsif key = auth._param(auth.unlock_account_key_param)
        if auth._account_from_unlock_key(key)
          if !auth.unlock_account_requires_password? || auth.password_match?(auth.param(auth.password_param))
            auth.unlock_account
            auth._after_unlock_account
            if auth.unlock_account_autologin?
              auth.update_session
            end
            auth.set_notice_flash auth.unlock_account_notice_flash
            r.redirect(auth.unlock_account_redirect)
          else
            @password_error = auth.invalid_password_message
            auth.set_error_flash auth.unlock_account_error_flash
            auth.unlock_account_view
          end
        end
      end
    end

    def _before_login_attempt
      if locked_out?
        set_error_flash login_error_flash
        response.write unlock_account_request_view
        request.halt
      end
      super
    end

    def _after_login
      clear_invalid_login_attempts
      super
    end

    def _after_login_failure
      invalid_login_attempted
      super
    end

    def _after_close_account
      remove_lockout_metadata
      super if defined?(super)
    end

    def unlock_account_route
      lockout_route
    end

    def account_login_failures_dataset
      db[account_login_failures_table].where(account_login_failures_id_column=>account_id_value)
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
        remove_lockout_metadata
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
        # :nocov:
        if ds.update(account_login_failures_number_column=>Sequel.expr(account_login_failures_number_column)+1) > 0
          ds.get(account_login_failures_number_column)
        end
        # :nocov:
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

    def remove_lockout_metadata
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
