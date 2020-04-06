# frozen-string-literal: true

module Rodauth
  Feature.define(:password_grace_period, :PasswordGracePeriod) do
    auth_value_method :password_grace_period, 300
    session_key :last_password_entry_session_key, :last_password_entry

    auth_methods :password_recently_entered?

    def modifications_require_password?
      return false unless super
      !password_recently_entered?
    end

    def password_match?(_)
      if v = super
        @last_password_entry = set_last_password_entry
      end
      v
    end

    def password_recently_entered?
      return false unless last_password_entry = session[last_password_entry_session_key]
      last_password_entry + password_grace_period > Time.now.to_i
    end

    def update_session
      super
      set_session_value(last_password_entry_session_key, @last_password_entry) if defined?(@last_password_entry)
    end

    private

    def after_create_account
      super if defined?(super)
      @last_password_entry = Time.now.to_i
    end

    def after_reset_password
      super if defined?(super)
      @last_password_entry = Time.now.to_i
    end

    def set_last_password_entry
      set_session_value(last_password_entry_session_key, Time.now.to_i)
    end

    def require_password_authentication?
      return true if defined?(super) && super
      !password_recently_entered?
    end
  end
end
