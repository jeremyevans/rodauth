# frozen-string-literal: true

module Rodauth
  Feature.define(:password_expiration, :PasswordExpiration) do
    depends :login, :change_password

    error_flash "Your password has expired and needs to be changed"
    error_flash "Your password cannot be changed yet", 'password_not_changeable_yet'

    redirect :password_not_changeable_yet 
    redirect(:password_change_needed){change_password_path}

    auth_value_method :allow_password_change_after, -86400
    auth_value_method :require_password_change_after, 90*86400
    auth_value_method :password_expiration_table, :account_password_change_times
    auth_value_method :password_expiration_id_column, :id
    auth_value_method :password_expiration_changed_at_column, :changed_at
    session_key :password_changed_at_session_key, :password_changed_at
    auth_value_method :password_expiration_default, false

    auth_methods(
      :password_expired?,
      :update_password_changed_at
    )

    def get_password_changed_at
      convert_timestamp(password_expiration_ds.get(password_expiration_changed_at_column))
    end

    def check_password_change_allowed
      if password_changed_at = get_password_changed_at
        if password_changed_at > Time.now - allow_password_change_after
          set_redirect_error_flash password_not_changeable_yet_error_flash
          redirect password_not_changeable_yet_redirect
        end
      end
    end

    def set_password(password)
      update_password_changed_at
      set_session_value(password_changed_at_session_key, Time.now.to_i)
      super
    end

    def account_from_reset_password_key(key)
      if a = super
        check_password_change_allowed
      end
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
      if authenticated? && password_expired? && password_change_needed_redirect != request.path_info
        set_redirect_error_flash password_expiration_error_flash
        redirect password_change_needed_redirect
      end
    end

    def password_expired?
      if password_changed_at = session[password_changed_at_session_key]
        return password_changed_at + require_password_change_after < Time.now.to_i
      end

      account_from_session
      if password_changed_at = get_password_changed_at
        set_session_value(password_changed_at_session_key, password_changed_at.to_i)
        password_changed_at + require_password_change_after < Time.now
      else
        set_session_value(password_changed_at_session_key, password_expiration_default ? 0 : 2147483647)
        password_expiration_default
      end
    end

    private

    def after_close_account
      super if defined?(super)
      password_expiration_ds.delete
    end

    def before_change_password_route
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

    def password_expiration_ds
      db[password_expiration_table].where(password_expiration_id_column=>account_id)
    end
  end
end
