module Rodauth
  PasswordGracePeriod = Feature.define(:password_grace_period) do
    auth_value_method :password_grace_period, 300
    auth_value_method :last_password_entry_session_key, :last_password_entry

    def modifications_require_password?
      return false unless super
      password_recently_entered?
    end

    def password_match?(_)
      if v = super
        @last_password_entry = set_last_password_entry
      end
      v
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

    def update_session
      super
      session[last_password_entry_session_key] = @last_password_entry if defined?(@last_password_entry)
    end

    def password_recently_entered?
      return false unless last_password_entry = session[last_password_entry_session_key]
      last_password_entry + password_grace_period < Time.now.to_i
    end

    def set_last_password_entry
      session[last_password_entry_session_key] = Time.now.to_i
    end
  end
end
