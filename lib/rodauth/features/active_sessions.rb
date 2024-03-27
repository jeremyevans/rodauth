# frozen-string-literal: true

module Rodauth
  Feature.define(:active_sessions, :ActiveSessions) do
    depends :logout

    error_flash 'This session has been logged out'
    redirect

    session_key :session_id_session_key, :active_session_id
    auth_value_method :active_sessions_account_id_column, :account_id
    auth_value_method :active_sessions_created_at_column, :created_at
    auth_value_method :active_sessions_last_use_column, :last_use
    auth_value_method :active_sessions_session_id_column, :session_id
    auth_value_method :active_sessions_table, :account_active_session_keys
    translatable_method :global_logout_label, 'Logout all Logged In Sessions?'
    auth_value_method :global_logout_param, 'global_logout'
    auth_value_method :inactive_session_error_status, 401
    auth_value_method :session_inactivity_deadline, 86400
    auth_value_method(:session_lifetime_deadline, 86400*30)

    auth_value_methods :update_current_session?

    auth_methods(
      :active_sessions_insert_hash,
      :active_sessions_key,
      :active_sessions_update_hash,
      :add_active_session,
      :currently_active_session?,
      :handle_duplicate_active_session_id,
      :no_longer_active_session,
      :remove_active_session,
      :remove_all_active_sessions,
      :remove_all_active_sessions_except_for,
      :remove_all_active_sessions_except_current,
      :remove_current_session,
      :remove_inactive_sessions,
    )

    def currently_active_session?
      return false unless session_id = session[session_id_session_key]

      remove_inactive_sessions
      ds = active_sessions_ds.
        where(active_sessions_session_id_column => compute_hmacs(session_id))

      if update_current_session?
        ds.update(active_sessions_update_hash) == 1
      else
        ds.count == 1
      end
    end

    def check_active_session
      if logged_in? && !currently_active_session?
        no_longer_active_session
      end
    end

    def no_longer_active_session
      clear_session
      set_redirect_error_status inactive_session_error_status
      set_error_reason :inactive_session
      set_redirect_error_flash active_sessions_error_flash
      redirect active_sessions_redirect
    end

    def add_active_session
      key = generate_active_sessions_key
      set_session_value(session_id_session_key, key)
      if e = raises_uniqueness_violation?{active_sessions_ds.insert(active_sessions_insert_hash)}
        handle_duplicate_active_session_id(e)
      end
      nil
    end

    def handle_duplicate_active_session_id(_e)
      # Do nothing by default as session is already tracked.  This will result in
      # the current session and the existing session with the same id
      # being tracked together, so that a logout of one will logout
      # the other, and updating the last use on one will update the other,
      # but this should be acceptable.  However, this can be overridden if different
      # behavior is desired.
    end

    def remove_current_session
      if session_id = session[session_id_session_key]
        remove_active_session(compute_hmacs(session_id))
      end
    end

    def remove_active_session(session_id)
      active_sessions_ds.where(active_sessions_session_id_column=>session_id).delete
    end

    def remove_all_active_sessions
      active_sessions_ds.delete
    end

    def remove_all_active_sessions_except_for(session_id)
      active_sessions_ds.exclude(active_sessions_session_id_column=>compute_hmacs(session_id)).delete
    end

    def remove_all_active_sessions_except_current 
      if session_id = session[session_id_session_key]
        remove_all_active_sessions_except_for(session_id)
      else
        remove_all_active_sessions
      end
    end

    def remove_inactive_sessions
      if cond = inactive_session_cond
        active_sessions_ds.where(cond).delete
      end
    end

    def logout_additional_form_tags
      super.to_s + render('global-logout-field')
    end

    def update_session
      remove_current_session
      super
      add_active_session
    end

    private

    def after_refresh_token
      super if defined?(super)
      if prev_key = session[session_id_session_key]
        key = generate_active_sessions_key
        set_session_value(session_id_session_key, key)
        active_sessions_ds.
          where(active_sessions_session_id_column => compute_hmacs(prev_key)).
          update(active_sessions_session_id_column => compute_hmac(key))
      end
    end

    def after_close_account
      super if defined?(super)
      remove_all_active_sessions
    end

    def before_logout
      if param_or_nil(global_logout_param)
        remove_remember_key(session_value) if respond_to?(:remove_remember_key)
        remove_all_active_sessions
      else
        remove_current_session
      end
      super
    end

    attr_reader :active_sessions_key

    def generate_active_sessions_key
      @active_sessions_key = random_key
    end

    def active_sessions_insert_hash
      {active_sessions_account_id_column => session_value, active_sessions_session_id_column => compute_hmac(active_sessions_key)}
    end

    def active_sessions_update_hash
      h = {active_sessions_last_use_column => Sequel::CURRENT_TIMESTAMP}

      if hmac_secret_rotation?
        h[active_sessions_session_id_column] = compute_hmac(session[session_id_session_key])
      end

      h
    end

    def session_inactivity_deadline_condition
      if deadline = session_inactivity_deadline
        Sequel[active_sessions_last_use_column] < Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: deadline)
      end
    end

    def session_lifetime_deadline_condition
      if deadline = session_lifetime_deadline
        Sequel[active_sessions_created_at_column] < Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: deadline)
      end
    end

    def inactive_session_cond
      cond = session_inactivity_deadline_condition
      cond2 = session_lifetime_deadline_condition
      return false unless cond || cond2
      Sequel.|(*[cond, cond2].compact)
    end

    def update_current_session?
      !!session_inactivity_deadline
    end

    def active_sessions_ds
      db[active_sessions_table].
        where(active_sessions_account_id_column=>session_value || account_id)
    end

    def use_date_arithmetic?
      true
    end
  end
end
