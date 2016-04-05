module Rodauth
  PasswordExpiration = Feature.define(:password_expiration) do
    depends :login, :change_password

    notice_flash "Your password has expired and needs to be changed"
    notice_flash "Your password cannot be changed yet", 'password_not_changeable_yet'

    redirect :password_not_changeable_yet 
    redirect(:password_change_needed){"#{prefix}/#{change_password_route}"}

    auth_value_method :allow_password_change_after, 0
    auth_value_method :require_password_change_after, 90*86400
    auth_value_method :password_expiration_table, :account_password_change_times
    auth_value_method :password_expiration_id_column, :id
    auth_value_method :password_expiration_changed_at_column, :changed_at
    auth_value_method :password_expiration_session_key, :password_expired

    auth_methods(
      :password_expired?,
      :update_password_changed_at
    )

    def before_change_password
      check_password_change_allowed
      super
    end

    def after_create_account
      if account_password_hash_column
        update_password_changed_at
      end
      super if defined?(super)
    end

    def after_login
      require_current_password
      super
    end

    def get_password_changed_at
      convert_timestamp(password_expiration_ds.get(password_expiration_changed_at_column))
    end

    def check_password_change_allowed
      if password_changed_at = get_password_changed_at
        if password_changed_at > Time.now - allow_password_change_after
          set_notice_flash password_not_changeable_yet_notice_flash
          request.redirect password_not_changeable_yet_redirect
        end
      end
    end

    def set_password(password)
      update_password_changed_at
      session.delete(password_expiration_session_key)
      super
    end

    def account_from_reset_password_key(key)
      a = super
      check_password_change_allowed
      a
    end

    def update_password_changed_at
      ds = password_expiration_ds
      if ds.update(password_expiration_changed_at_column=>Sequel::CURRENT_TIMESTAMP) == 0
        # Ignoring the violation is safe here, since a concurrent insert would also set it to the
        # current timestamp.
        ignore_uniqueness_violation{ds.insert(password_expiration_id_column=>account_id)}
      end
    end

    def require_current_password
      if authenticated? && password_expired?
        set_notice_flash password_expiration_notice_flash
        request.redirect password_change_needed_redirect
      end
    end

    def password_expired?
      if session.has_key?(password_expiration_session_key)
        return session[password_expiration_session_key]
      end

      account_from_session
      session[password_expiration_session_key] = if password_changed_at = get_password_changed_at || false
        password_changed_at < Time.now - require_password_change_after
      end
    end

    def after_close_account
      super if defined?(super)
      password_expiration_ds.delete
    end

    private

    def password_expiration_ds
      db[password_expiration_table].where(password_expiration_id_column=>account_id)
    end
  end
end
