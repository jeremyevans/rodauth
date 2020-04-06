# frozen-string-literal: true

module Rodauth
  Feature.define(:account_expiration, :AccountExpiration) do
    error_flash "You cannot log into this account as it has expired"
    redirect
    after

    auth_value_method :account_activity_expired_column, :expired_at
    auth_value_method :account_activity_id_column, :id
    auth_value_method :account_activity_last_activity_column, :last_activity_at
    auth_value_method :account_activity_last_login_column, :last_login_at
    auth_value_method :account_activity_table, :account_activity_times
    auth_value_method :expire_account_after, 180*86400
    auth_value_method :expire_account_on_last_activity?, false

    auth_methods(
      :account_expired?,
      :account_expired_at,
      :last_account_activity_at,
      :last_account_login_at,
      :set_expired,
      :update_last_activity,
      :update_last_login
    )

    def last_account_activity_at
      get_activity_timestamp(session_value, account_activity_last_activity_column)
    end

    def last_account_login_at
      get_activity_timestamp(session_value, account_activity_last_login_column)
    end

    def account_expired_at
      get_activity_timestamp(account_id, account_activity_expired_column)
    end

    def update_last_login
      update_activity(account_id, account_activity_last_login_column, account_activity_last_activity_column)
    end

    def update_last_activity
      if session_value
        update_activity(session_value, account_activity_last_activity_column)
      end
    end

    def set_expired
      update_activity(account_id, account_activity_expired_column)
      after_account_expiration
    end

    def account_expired?
      columns = [account_activity_last_activity_column, account_activity_last_login_column, account_activity_expired_column]
      last_activity, last_login, expired = account_activity_ds(account_id).get(columns)
      return true if expired
      timestamp = convert_timestamp(expire_account_on_last_activity? ? last_activity : last_login)
      return false unless timestamp
      timestamp < Time.now - expire_account_after
    end

    def check_account_expiration
      if account_expired?
        set_expired unless account_expired_at
        set_redirect_error_flash account_expiration_error_flash
        redirect account_expiration_redirect
      end
      update_last_login
    end

    def update_session
      check_account_expiration
      super
    end

    private

    def before_reset_password
      check_account_expiration
      super if defined?(super)
    end

    def before_reset_password_request
      check_account_expiration
      super if defined?(super)
    end

    def before_unlock_account
      check_account_expiration
      super if defined?(super)
    end

    def before_unlock_account_request
      check_account_expiration
      super if defined?(super)
    end

    def after_close_account
      super if defined?(super)
      account_activity_ds(account_id).delete
    end

    def account_activity_ds(account_id)
      db[account_activity_table].
        where(account_activity_id_column=>account_id)
    end

    def get_activity_timestamp(account_id, column)
      convert_timestamp(account_activity_ds(account_id).get(column))
    end

    def update_activity(account_id, *columns)
      ds = account_activity_ds(account_id)
      hash = {}
      columns.each do |c|
        hash[c] = Sequel::CURRENT_TIMESTAMP
      end
      if ds.update(hash) == 0
        hash[account_activity_id_column] = account_id
        hash[account_activity_last_activity_column] ||= Sequel::CURRENT_TIMESTAMP
        hash[account_activity_last_login_column] ||= Sequel::CURRENT_TIMESTAMP
        # It is safe to ignore uniqueness violations here, as a concurrent insert would also use current timestamps.
        ignore_uniqueness_violation{ds.insert(hash)}
      end
    end
  end
end
