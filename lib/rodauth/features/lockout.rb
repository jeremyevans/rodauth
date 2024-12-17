# frozen-string-literal: true

module Rodauth
  Feature.define(:lockout, :Lockout) do
    depends :login, :email_base

    loaded_templates %w'unlock-account-request unlock-account password-field unlock-account-email'
    view 'unlock-account-request', 'Request Account Unlock', 'unlock_account_request'
    view 'unlock-account', 'Unlock Account', 'unlock_account'
    before 'unlock_account'
    before 'unlock_account_request'
    after 'unlock_account'
    after 'unlock_account_request'
    after 'account_lockout'
    additional_form_tags 'unlock_account'
    additional_form_tags 'unlock_account_request'
    button 'Unlock Account', 'unlock_account'
    button 'Request Account Unlock', 'unlock_account_request'
    error_flash "There was an error unlocking your account", 'unlock_account'
    error_flash "This account is currently locked out and cannot be logged in to", "login_lockout"
    error_flash "An email has recently been sent to you with a link to unlock the account", 'unlock_account_email_recently_sent'
    error_flash "There was an error unlocking your account: invalid or expired unlock account key", 'no_matching_unlock_account_key'
    notice_flash "Your account has been unlocked", 'unlock_account'
    notice_flash "An email has been sent to you with a link to unlock your account", 'unlock_account_request'
    redirect :unlock_account
    response :unlock_account
    response :unlock_account_request
    redirect(:unlock_account_request){default_post_email_redirect}
    redirect(:unlock_account_email_recently_sent){default_post_email_redirect}
    email :unlock_account, 'Unlock Account'

    auth_value_method :unlock_account_autologin?, true
    auth_value_method :max_invalid_logins, 100
    auth_value_method :account_login_failures_table, :account_login_failures
    auth_value_method :account_login_failures_id_column, :id
    auth_value_method :account_login_failures_number_column, :number
    auth_value_method :account_lockouts_table, :account_lockouts
    auth_value_method :account_lockouts_id_column, :id
    auth_value_method :account_lockouts_key_column, :key
    auth_value_method :account_lockouts_email_last_sent_column, :email_last_sent
    auth_value_method :account_lockouts_deadline_column, :deadline
    auth_value_method :account_lockouts_deadline_interval, {:days=>1}.freeze
    translatable_method :unlock_account_explanatory_text, '<p>This account is currently locked out.  You can unlock the account:</p>'
    translatable_method :unlock_account_request_explanatory_text, '<p>This account is currently locked out.  You can request that the account be unlocked:</p>'
    auth_value_method :unlock_account_key_param, 'key'
    auth_value_method :unlock_account_requires_password?, false
    auth_value_method :unlock_account_skip_resend_email_within, 300
    session_key :unlock_account_session_key, :unlock_account_key

    auth_methods(
      :clear_invalid_login_attempts,
      :generate_unlock_account_key,
      :get_unlock_account_key,
      :get_unlock_account_email_last_sent,
      :invalid_login_attempted,
      :locked_out?,
      :set_unlock_account_email_last_sent,
      :unlock_account_email_link,
      :unlock_account,
      :unlock_account_key
    )
    auth_private_methods :account_from_unlock_key

    internal_request_method(:lock_account)
    internal_request_method(:unlock_account_request)
    internal_request_method(:unlock_account)

    route(:unlock_account_request) do |r|
      check_already_logged_in
      before_unlock_account_request_route

      r.post do
        if account_from_login(login_param_value) && get_unlock_account_key
          if unlock_account_email_recently_sent?
            set_redirect_error_flash unlock_account_email_recently_sent_error_flash
            redirect unlock_account_email_recently_sent_redirect
          end

          @unlock_account_key_value = get_unlock_account_key
          transaction do
            before_unlock_account_request
            set_unlock_account_email_last_sent
            send_unlock_account_email
            after_unlock_account_request
          end

          unlock_account_request_response
        else
          set_redirect_error_status(no_matching_login_error_status)
          set_error_reason :no_matching_login
          set_redirect_error_flash no_matching_login_message.to_s.capitalize
          redirect unlock_account_request_redirect
        end
      end
    end

    route(:unlock_account) do |r|
      check_already_logged_in
      before_unlock_account_route

      r.get do
        if key = param_or_nil(unlock_account_key_param)
          set_session_value(unlock_account_session_key, key)
          redirect(r.path)
        end

        if (key = session[unlock_account_session_key]) && account_from_unlock_key(key)
          unlock_account_view
        else
          remove_session_value(unlock_account_session_key)
          set_redirect_error_flash no_matching_unlock_account_key_error_flash
          redirect require_login_redirect
        end
      end

      r.post do
        key = session[unlock_account_session_key] || param(unlock_account_key_param)
        unless account_from_unlock_key(key)
          set_redirect_error_status invalid_key_error_status
          set_error_reason :invalid_unlock_account_key
          set_redirect_error_flash no_matching_unlock_account_key_error_flash
          redirect unlock_account_request_redirect
        end

        if !unlock_account_requires_password? || password_match?(param(password_param))
          transaction do
            before_unlock_account
            unlock_account
            after_unlock_account
            if unlock_account_autologin?
              autologin_session('unlock_account')
            end
          end

          remove_session_value(unlock_account_session_key)
          unlock_account_response
        else
          set_response_error_reason_status(:invalid_password, invalid_password_error_status)
          set_field_error(password_param, invalid_password_message)
          set_error_flash unlock_account_error_flash
          unlock_account_view
        end
      end
    end

    def locked_out?
      if t = convert_timestamp(account_lockouts_ds.get(account_lockouts_deadline_column))
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

    def clear_invalid_login_attempts
      unlock_account
    end

    def _setup_account_lockouts_hash(account_id, key)
      hash = {account_lockouts_id_column=>account_id, account_lockouts_key_column=>key}
      set_deadline_value(hash, account_lockouts_deadline_column, account_lockouts_deadline_interval)
      hash
    end

    def invalid_login_attempted
      ds = account_login_failures_ds.
          where(account_login_failures_id_column=>account_id)

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
        # Ignoring the violation is safe here.  It may allow slightly more than max_invalid_logins invalid logins before
        # lockout, but allowing a few extra is OK if the race is lost.
        ignore_uniqueness_violation{account_login_failures_ds.insert(account_login_failures_id_column=>account_id)}
        number = 1
      end

      if number >= max_invalid_logins
        @unlock_account_key_value = generate_unlock_account_key
        hash = _setup_account_lockouts_hash(account_id, unlock_account_key_value)

        if e = raised_uniqueness_violation{account_lockouts_ds.insert(hash)}
          # If inserting into the lockout table raises a violation, we should just be able to pull the already inserted
          # key out of it.  If that doesn't return a valid key, we should reraise the error.
          raise e unless @unlock_account_key_value = account_lockouts_ds.get(account_lockouts_key_column)

          after_account_lockout
          show_lockout_page
        else
          after_account_lockout
          e
        end
      end
    end

    def get_unlock_account_key
      account_lockouts_ds.get(account_lockouts_key_column)
    end

    def account_from_unlock_key(key)
      @account = _account_from_unlock_key(key)
    end

    def unlock_account_email_link
      token_link(unlock_account_route, unlock_account_key_param, unlock_account_key_value)
    end

    def get_unlock_account_email_last_sent
      if column = account_lockouts_email_last_sent_column
        if ts = account_lockouts_ds.get(column)
          convert_timestamp(ts)
        end
      end
    end

    def set_unlock_account_email_last_sent
      account_lockouts_ds.update(account_lockouts_email_last_sent_column=>Sequel::CURRENT_TIMESTAMP) if account_lockouts_email_last_sent_column
    end

    def unlock_account_email_recently_sent?
      (email_last_sent = get_unlock_account_email_last_sent) && (Time.now - email_last_sent < unlock_account_skip_resend_email_within)
    end

    private

    attr_reader :unlock_account_key_value

    def before_login_attempt
      if locked_out?
        show_lockout_page
      end
      super
    end

    def after_login
      clear_invalid_login_attempts
      super
    end

    def after_login_failure
      invalid_login_attempted
      super
    end

    def after_close_account
      remove_lockout_metadata
      super if defined?(super)
    end

    def generate_unlock_account_key
      random_key
    end

    def remove_lockout_metadata
      account_login_failures_ds.delete
      account_lockouts_ds.delete
    end

    def show_lockout_page
      set_response_error_reason_status(:account_locked_out, lockout_error_status)
      set_error_flash login_lockout_error_flash
      return_response unlock_account_request_view
    end

    def use_date_arithmetic?
      super || db.database_type == :mysql
    end

    def account_login_failures_ds
      db[account_login_failures_table].where(account_login_failures_id_column=>account_id)
    end

    def account_lockouts_ds(id=account_id)
      db[account_lockouts_table].where(account_lockouts_id_column=>id)
    end

    def _account_from_unlock_key(token)
      account_from_key(token){|id| account_lockouts_ds(id).get(account_lockouts_key_column)}
    end
  end
end
