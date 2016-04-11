module Rodauth
  VerifyAccountGracePeriod = Feature.define(:verify_account_grace_period) do
    depends :verify_account

    auth_value_method :account_created_at_column, :created_at
    auth_value_method :unverified_account_session_key, :unverified_account
    auth_value_method :verify_account_grace_period, 86400

    auth_methods(
      :account_created_at,
      :account_in_unverified_grace_period?
    )

    def verified_account?
      logged_in? && !session[unverified_account_session_key]
    end

    def create_account_autologin?
      true
    end

    def account_created_at
      convert_timestamp(account[account_created_at_column])
    end

    def open_account?
      super || account_in_unverified_grace_period?
    end

    private

    def after_create_account
      super
      account[account_created_at_column] = Time.now
    end

    def verify_account_check_already_logged_in
      nil
    end

    def account_session_status_filter
      s = super
      if verify_account_grace_period
        s = Sequel.|(s, Sequel.expr(account_status_column=>account_unverified_status_value) & (Sequel.date_add(account_created_at_column, :seconds=>verify_account_grace_period) > Sequel::CURRENT_TIMESTAMP))
      end
      s
    end

    def update_session
      super
      if account_in_unverified_grace_period?
        session[unverified_account_session_key] = true
      end
    end

    def account_in_unverified_grace_period?
      account[account_status_column] == account_unverified_status_value &&
        verify_account_grace_period &&
        account_created_at &&
        account_created_at + verify_account_grace_period > Time.now
    end

    def use_date_arithmetic?
      true
    end
  end
end
