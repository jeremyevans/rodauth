module Rodauth
  SessionExpiration = Feature.define(:session_expiration) do
    error_flash "This session has expired, please login again."

    auth_value_method :max_session_lifetime, 86400
    auth_value_method :session_created_session_key, :session_created_at
    auth_value_method :session_expiration_default, true
    auth_value_method :session_inactivity_timeout, 1800
    auth_value_method :session_last_activity_session_key, :last_session_activity_at

    auth_value_methods :session_expiration_redirect
    
    def check_session_expiration
      return unless logged_in?

      unless session.has_key?(session_last_activity_session_key) && session.has_key?(session_created_session_key)
        if session_expiration_default
          expire_session
        end

        return
      end

      time = Time.now.to_i

      if session[session_last_activity_session_key] + session_inactivity_timeout < time
        expire_session
      end
      set_session_value(session_last_activity_session_key, time)

      if session[session_created_session_key] + max_session_lifetime < time
        expire_session
      end
    end

    def expire_session
      clear_session
      set_redirect_error_flash session_expiration_error_flash
      redirect session_expiration_redirect
    end

    def session_expiration_redirect
      require_login_redirect
    end

    private

    def update_session
      super
      session[session_last_activity_session_key] = session[session_created_session_key] = Time.now.to_i
    end
  end
end
