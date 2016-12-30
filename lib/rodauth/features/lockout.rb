# frozen-string-literal: true

module Rodauth
  Lockout = Feature.define(:lockout) do
    depends :login, :email_base

    view 'unlock-account-request', 'Request Account Unlock', 'unlock_account_request'
    view 'unlock-account', 'Unlock Account', 'unlock_account'
    before 'unlock_account'
    before 'unlock_account_request'
    after 'unlock_account'
    after 'unlock_account_request'
    additional_form_tags 'unlock_account'
    additional_form_tags 'unlock_account_request'
    button 'Unlock Account', 'unlock_account'
    button 'Request Account Unlock', 'unlock_account_request'
    error_flash "There was an error unlocking your account", 'unlock_account'
    error_flash "This account is currently locked out and cannot be logged in to.", "login_lockout"
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
    auth_value_method :no_matching_unlock_account_key_message, 'No matching unlock account key'
    auth_value_method :unlock_account_email_subject, 'Unlock Account'
    auth_value_method :unlock_account_key_param, 'key'
    auth_value_method :unlock_account_requires_password?, false
    auth_value_method :unlock_account_session_key, :unlock_account_key

    auth_value_methods(
      :unlock_account_redirect,
      :unlock_account_request_redirect
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
    auth_private_methods :account_from_unlock_key

    route(:unlock_account_request) do |r|
      check_already_logged_in
      before_unlock_account_request_route

      r.post do
        if account_from_login(param(login_param)) && get_unlock_account_key
          transaction do
            before_unlock_account_request
            send_unlock_account_email
            after_unlock_account_request
          end

          set_notice_flash unlock_account_request_notice_flash
        else
          set_redirect_error_status(no_matching_login_error_status)
          set_redirect_error_flash no_matching_login_message
        end

        redirect unlock_account_request_redirect
      end
    end

    route(:unlock_account) do |r|
      check_already_logged_in
      before_unlock_account_route

      r.get do
        if key = param_or_nil(unlock_account_key_param)
          session[unlock_account_session_key] = key
          redirect(r.path)
        end

        if key = session[unlock_account_session_key]
          if account_from_unlock_key(key)
            unlock_account_view
          else
            session[unlock_account_session_key] = nil
            set_redirect_error_flash no_matching_unlock_account_key_message
            redirect require_login_redirect
          end
        end
      end

      r.post do
        key = session[unlock_account_session_key] || param(unlock_account_key_param)
        unless account_from_unlock_key(key)
          set_redirect_error_status invalid_key_error_status
          set_redirect_error_flash no_matching_unlock_account_key_message
          redirect unlock_account_request_redirect
        end

        if !unlock_account_requires_password? || password_match?(param(password_param))
          transaction do
            before_unlock_account
            unlock_account
            after_unlock_account
            if unlock_account_autologin?
              update_session
            end
          end

          session[unlock_account_session_key] = nil
          set_notice_flash unlock_account_notice_flash
          redirect unlock_account_redirect
        else
          set_response_error_status(invalid_password_error_status)
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
        hash = {account_lockouts_id_column=>account_id, account_lockouts_key_column=>unlock_account_key_value}
        set_deadline_value(hash, account_lockouts_deadline_column, account_lockouts_deadline_interval)

        if e = raised_uniqueness_violation{account_lockouts_ds.insert(hash)}
          # If inserting into the lockout table raises a violation, we should just be able to pull the already inserted
          # key out of it.  If that doesn't return a valid key, we should reraise the error.
          raise e unless @unlock_account_key_value = account_lockouts_ds.get(account_lockouts_key_column)

          show_lockout_page
        end
      end
    end

    def get_unlock_account_key
      account_lockouts_ds.get(account_lockouts_key_column)
    end

    def account_from_unlock_key(key)
      @account = _account_from_unlock_key(key)
    end

    def send_unlock_account_email
      @unlock_account_key_value = get_unlock_account_key
      create_unlock_account_email.deliver!
    end

    def unlock_account_email_link
      token_link(unlock_account_route, unlock_account_key_param, unlock_account_key_value)
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
      set_response_error_status lockout_error_status
      set_error_flash login_lockout_error_flash
      response.write unlock_account_request_view
      request.halt
    end

    def create_unlock_account_email
      create_email(unlock_account_email_subject, unlock_account_email_body)
    end

    def unlock_account_email_body
      render('unlock-account-email')
    end

    def use_date_arithmetic?
      db.database_type == :mysql
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
