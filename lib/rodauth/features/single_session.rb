module Rodauth
  SingleSession = Feature.define(:single_session) do
    notice_flash 'This session has been logged out as another session has become active'
    redirect

    auth_value_method :single_session_id_column, :id
    auth_value_method :single_session_key_column, :key
    auth_value_method :single_session_session_key, :single_session_key
    auth_value_method :single_session_table, :account_session_keys

    auth_methods(
      :currently_active_session?,
      :no_longer_active_session,
      :reset_single_session_key,
      :update_single_session_key
    )

    def update_session
      super
      update_single_session_key
    end

    def reset_single_session_key
      if logged_in?
        single_session_ds.update(single_session_key_column=>random_key)
      end
    end

    def _before_logout
      reset_single_session_key if request.post?
      super if defined?(super)
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
        timing_safe_eql?(single_session_key, current_key)
      end
    end

    def check_single_session
      if logged_in? && !currently_active_session?
        no_longer_active_session
      end
    end

    def no_longer_active_session
      clear_session
      set_notice_flash single_session_notice_flash
      request.redirect single_session_redirect
    end

    def update_single_session_key
      key = random_key
      session[single_session_session_key] = key
      if single_session_ds.update(single_session_key_column=>key) == 0
        # Don't handle uniqueness violations here.  While we could get the stored key from the
        # database, it could lead to two sessions sharing the same key, which this feature is
        # designed to prevent.
        single_session_ds.insert(single_session_id_column=>session_value, single_session_key_column=>key)
      end
    end

    def _after_close_account
      super if defined?(super)
      single_session_ds.delete
    end

    private

    def single_session_ds
      db[single_session_table].
        where(single_session_id_column=>session_value)
    end
  end
end
