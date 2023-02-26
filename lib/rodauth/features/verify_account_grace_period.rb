# frozen-string-literal: true

module Rodauth
  Feature.define(:verify_account_grace_period, :VerifyAccountGracePeriod) do
    depends :verify_account
    error_flash "Please verify this account before changing the login", "unverified_change_login"
    redirect :unverified_change_login

    auth_value_method :verification_requested_at_column, :requested_at
    session_key :unverified_account_session_key, :unverified_account
    auth_value_method :verify_account_grace_period, 86400

    auth_methods(
      :account_in_unverified_grace_period?
    )

    def verified_account?
      logged_in? && !session[unverified_account_session_key]
    end

    def create_account_autologin?
      true
    end

    def open_account?
      super || (account_in_unverified_grace_period? && has_password?)
    end

    def verify_account_set_password?
      false
    end

    def logged_in?
      super && !unverified_grace_period_expired?
    end

    def require_login
      if unverified_grace_period_expired?
        clear_session
      end
      super
    end

    def update_session
      super
      if account_in_unverified_grace_period?
        set_session_value(unverified_account_session_key, Time.now.to_i + verify_account_grace_period)
      end
    end

    private

    def after_close_account
      super if defined?(super)
      verify_account_ds.delete
    end
    
    def before_change_login_route
      unless verified_account?
        set_redirect_error_flash unverified_change_login_error_flash
        redirect unverified_change_login_redirect
      end
      super if defined?(super)
    end

    def allow_email_auth?
      (defined?(super) ? super : true) && !account_in_unverified_grace_period?
    end

    def verify_account_check_already_logged_in
      nil
    end

    def account_session_status_filter
      s = super
      if verify_account_grace_period
        grace_period_ds = db[verify_account_table].
          select(verify_account_id_column).
          where((Sequel.date_add(verification_requested_at_column, :seconds=>verify_account_grace_period) > Sequel::CURRENT_TIMESTAMP))
        s = Sequel.|(s, Sequel.expr(account_status_column=>account_unverified_status_value) & {account_id_column => grace_period_ds})
      end
      s
    end

    def account_in_unverified_grace_period?
      return false unless account!
      account[account_status_column] == account_unverified_status_value &&
        verify_account_grace_period &&
        !verify_account_ds.where(Sequel.date_add(verification_requested_at_column, :seconds=>verify_account_grace_period) > Sequel::CURRENT_TIMESTAMP).empty?
    end

    def unverified_grace_period_expired?
      return false unless expires_at = session[unverified_account_session_key]
      expires_at.is_a?(Integer) && Time.now.to_i > expires_at
    end

    def use_date_arithmetic?
      true
    end
  end
end
