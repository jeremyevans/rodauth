# frozen-string-literal: true

module Rodauth
  Feature.define(:active_sessions, :ActiveSessions) do
    error_flash 'This session has been logged out'
    redirect

    session_key :session_id_session_key, :session_id
    auth_value_method :active_sessions_account_id_column, :account_id
    auth_value_method :active_sessions_created_at_column, :created_at
    auth_value_method :active_sessions_last_use_column, :last_use
    auth_value_method :active_sessions_session_id_column, :session_id
    auth_value_method :active_sessions_table, :account_active_session_keys
    auth_value_method :global_logout_label, 'Logout all Logged In Sessons?'
    auth_value_method :global_logout_param, 'global_logout'
    auth_value_method :session_inactivity_deadline, 86400
    auth_value_method(:session_lifetime_deadline, 86400*30)

    auth_methods(
      :add_active_session,
      :currently_active_session?,
      :handle_duplicate_active_session_id,
      :no_longer_active_session,
      :remove_all_active_sessions,
      :remove_current_session,
      :remove_inactive_sessions,
    )

    def currently_active_session?
      return false unless session_id = session[session_id_session_key]

      remove_inactive_sessions
      ds = active_sessions_ds.
        where(active_sessions_session_id_column => compute_hmac(session_id))

      if session_inactivity_deadline
        ds.update(active_sessions_last_use_column => Sequel::CURRENT_TIMESTAMP) == 1
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
      set_redirect_error_flash active_sessions_error_flash
      redirect active_sessions_redirect
    end

    def add_active_session
      key = random_key
      set_session_value(session_id_session_key, key)
      if e = raises_uniqueness_violation? do
          active_sessions_ds.insert(active_sessions_account_id_column => session_value, active_sessions_session_id_column => compute_hmac(key))
        end
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
      active_sessions_ds.where(active_sessions_session_id_column=>compute_hmac(session[session_id_session_key])).delete
    end

    def remove_all_active_sessions
      active_sessions_ds.delete
    end

    def remove_inactive_sessions
      if cond = inactive_session_cond
        active_sessions_ds.where(cond).delete
      end
    end

    def logout_additional_form_tags
      input = input_field_string(global_logout_param, "rodauth-global-logout", :type=>'checkbox', :skip_error_message=>true, :value=>'t', :required=>false)
      input = "<label class=\"rodauth-global-logout-label\">#{input} #{global_logout_label}</label>"
      super.to_s + input
    end

    private

    def after_close_account
      super if defined?(super)
      remove_all_active_sessions
    end

    def before_logout
      if request.post?
        if param_or_nil(global_logout_param)
          remove_all_active_sessions
        else
          remove_current_session
        end
      end
      super if defined?(super)
    end

    def update_session
      super
      add_active_session
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

    def active_sessions_ds
      db[active_sessions_table].
        where(active_sessions_account_id_column=>session_value)
    end

    def use_date_arithmetic?
      true
    end
  end
end

