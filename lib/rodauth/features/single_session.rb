# frozen-string-literal: true

module Rodauth
  Feature.define(:single_session, :SingleSession) do
    error_flash 'This session has been logged out as another session has become active'
    redirect

    auth_value_method :allow_raw_single_session_key?, false
    auth_value_method :inactive_session_error_status, 401
    auth_value_method :single_session_id_column, :id
    auth_value_method :single_session_key_column, :key
    session_key :single_session_session_key, :single_session_key
    auth_value_method :single_session_table, :account_session_keys

    auth_methods(
      :currently_active_session?,
      :no_longer_active_session,
      :reset_single_session_key,
      :update_single_session_key
    )

    def reset_single_session_key
      if logged_in?
        single_session_ds.update(single_session_key_column=>random_key)
      end
    end

    def currently_active_session?
      single_session_key = session[single_session_session_key]
      current_key = single_session_ds.get(single_session_key_column)
      if single_session_key.nil?
        unless current_key
          # No row exists for this user, indicating the feature has never
          # been used, so it is OK to treat the current session as a new
          # session.
          update_single_session_key
        end
        true
      elsif current_key
        if hmac_secret && !(valid = timing_safe_eql?(single_session_key, hmac = compute_hmac(current_key)))
          if hmac_secret_rotation? && (valid = timing_safe_eql?(single_session_key, compute_old_hmac(current_key)))
            session[single_session_session_key] = hmac
          elsif !allow_raw_single_session_key?
            return false
          end
        end

        valid || timing_safe_eql?(single_session_key, current_key)
      end
    end

    def check_single_session
      if logged_in? && !currently_active_session?
        no_longer_active_session
      end
    end

    def no_longer_active_session
      clear_session
      set_redirect_error_status inactive_session_error_status
      set_error_reason :inactive_session
      set_redirect_error_flash single_session_error_flash
      redirect single_session_redirect
    end

    def update_single_session_key
      key = random_key
      set_single_session_key(key)
      if single_session_ds.update(single_session_key_column=>key) == 0
        # Don't handle uniqueness violations here.  While we could get the stored key from the
        # database, it could lead to two sessions sharing the same key, which this feature is
        # designed to prevent.
        single_session_ds.insert(single_session_id_column=>session_value, single_session_key_column=>key)
      end
    end

    def update_session
      super
      update_single_session_key
    end

    private

    def after_close_account
      super if defined?(super)
      single_session_ds.delete
    end

    def before_logout
      reset_single_session_key
      super if defined?(super)
    end

    def set_single_session_key(data)
      data = compute_hmac(data) if hmac_secret
      set_session_value(single_session_session_key, data)
    end

    def single_session_ds
      db[single_session_table].
        where(single_session_id_column=>session_value)
    end
  end
end
