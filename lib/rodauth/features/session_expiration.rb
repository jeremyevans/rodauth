# frozen-string-literal: true

module Rodauth
  Feature.define(:session_expiration, :SessionExpiration) do
    error_flash "This session has expired, please login again"
    redirect{require_login_redirect}

    auth_value_method :max_session_lifetime, 86400
    session_key :session_created_session_key, :session_created_at
    auth_value_method :session_expiration_error_status, 401
    auth_value_method :session_expiration_default, true
    auth_value_method :session_inactivity_timeout, 1800
    session_key :session_last_activity_session_key, :last_session_activity_at

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
      set_redirect_error_status session_expiration_error_status
      set_error_reason :session_expired
      set_redirect_error_flash session_expiration_error_flash
      redirect session_expiration_redirect
    end

    def update_session
      super
      t = Time.now.to_i
      set_session_value(session_last_activity_session_key, t)
      set_session_value(session_created_session_key, t)
    end
  end
end
