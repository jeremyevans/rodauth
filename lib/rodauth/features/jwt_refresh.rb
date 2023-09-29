# frozen-string-literal: true

module Rodauth
  Feature.define(:jwt_refresh, :JwtRefresh) do
    depends :jwt

    after 'refresh_token'
    before 'refresh_token'

    auth_value_method :allow_refresh_with_expired_jwt_access_token?, false
    session_key :jwt_refresh_token_data_session_key, :jwt_refresh_token_data
    session_key :jwt_refresh_token_hmac_session_key, :jwt_refresh_token_hash
    auth_value_method :jwt_access_token_key, 'access_token'
    auth_value_method :jwt_access_token_not_before_period, 5
    auth_value_method :jwt_access_token_period, 1800
    translatable_method :jwt_refresh_invalid_token_message, 'invalid JWT refresh token'
    auth_value_method :jwt_refresh_token_account_id_column, :account_id
    auth_value_method :jwt_refresh_token_deadline_column, :deadline
    auth_value_method :jwt_refresh_token_deadline_interval, {:days=>14}.freeze
    auth_value_method :jwt_refresh_token_id_column, :id
    auth_value_method :jwt_refresh_token_key, 'refresh_token'
    auth_value_method :jwt_refresh_token_key_column, :key
    auth_value_method :jwt_refresh_token_key_param, 'refresh_token'
    auth_value_method :jwt_refresh_token_table, :account_jwt_refresh_keys
    translatable_method :jwt_refresh_without_access_token_message, 'no JWT access token provided during refresh'
    auth_value_method :jwt_refresh_without_access_token_status, 401
    translatable_method :expired_jwt_access_token_message, "expired JWT access token"
    auth_value_method :expired_jwt_access_token_status, 400

    auth_private_methods(
      :account_from_refresh_token
    )

    route do |r|
      @jwt_refresh_route = true
      before_jwt_refresh_route

      r.post do
        if !session_value
          response.status ||= jwt_refresh_without_access_token_status
          json_response[json_response_error_key] = jwt_refresh_without_access_token_message
        elsif (refresh_token = param_or_nil(jwt_refresh_token_key_param)) && account_from_refresh_token(refresh_token)
          transaction do
            before_refresh_token
            formatted_token = generate_refresh_token
            remove_jwt_refresh_token_key(refresh_token)
            set_jwt_refresh_token_hmac_session_key(formatted_token)
            json_response[jwt_refresh_token_key] = formatted_token
            json_response[jwt_access_token_key] = session_jwt
            after_refresh_token
          end
        else
          json_response[json_response_error_key] = jwt_refresh_invalid_token_message
        end
        _return_json_response
      end
    end

    def update_session
      super

      # JWT login puts the access token in the header.
      # We put the refresh token in the body.
      # Note, do not put the access_token in the body here, as the access token content is not yet finalised.
      token = json_response[jwt_refresh_token_key] = generate_refresh_token

      set_jwt_refresh_token_hmac_session_key(token)
    end

    def set_jwt_token(token)
      super
      if json_response[json_response_error_key]
        json_response.delete(jwt_access_token_key)
      else
        json_response[jwt_access_token_key] = token
      end
    end

    def jwt_session_hash
      h = super
      t = Time.now.to_i
      h[:exp] = t + jwt_access_token_period
      h[:iat] = t
      h[:nbf] = t - jwt_access_token_not_before_period
      h
    end

    def account_from_refresh_token(token)
      @account = _account_from_refresh_token(token)
    end

    private

    def rescue_jwt_payload(e)
      if e.instance_of?(JWT::ExpiredSignature)
        begin
          # Some versions of jwt will raise JWT::ExpiredSignature even when the
          # JWT is invalid for other reasons.  Make sure the expiration is the
          # only reason the JWT isn't valid before treating this as an expired token.
          JWT.decode(jwt_token, jwt_secret, true, Hash[jwt_decode_opts].merge!(:verify_expiration=>false, :algorithm=>jwt_algorithm))[0]
        rescue
        else
          json_response[json_response_error_key] = expired_jwt_access_token_message
          response.status ||= expired_jwt_access_token_status
        end
      end

      super
    end

    def _account_from_refresh_token(token)
      id, token_id, key = _account_refresh_token_split(token)

      unless key &&
             (id.to_s == session_value.to_s) &&
             (actual = get_active_refresh_token(id, token_id)) &&
             (timing_safe_eql?(key, convert_token_key(actual)) || (hmac_secret_rotation? && timing_safe_eql?(key, compute_old_hmac(actual)))) &&
             jwt_refresh_token_match?(key)
        return
      end

      ds = account_ds(id)
      ds = ds.where(account_session_status_filter) unless skip_status_checks?
      ds.first
    end

    def _account_refresh_token_split(token)
      id, token = split_token(token)
      id = convert_token_id(id)
      return unless id && token

      token_id, key = split_token(token)
      token_id = convert_token_id(token_id)
      return unless token_id && key

      [id, token_id, key]
    end

    def _jwt_decode_opts
      if allow_refresh_with_expired_jwt_access_token? && (@jwt_refresh_route || request.path == jwt_refresh_path)
        Hash[super].merge!(:verify_expiration=>false)
      else
        super
      end
    end

    def jwt_refresh_token_match?(key)
      # We don't need to match tokens if we are requiring a valid current access token
      return true unless allow_refresh_with_expired_jwt_access_token?

      # If allowing with expired jwt access token, check the expired session contains
      # hmac matching submitted and active refresh token.
      s = session[jwt_refresh_token_hmac_session_key].to_s
      h = session[jwt_refresh_token_data_session_key].to_s + key
      timing_safe_eql?(compute_hmac(h), s) || (hmac_secret_rotation? && timing_safe_eql?(compute_old_hmac(h), s))
    end

    def get_active_refresh_token(account_id, token_id)
      jwt_refresh_token_account_ds(account_id).
        where(Sequel::CURRENT_TIMESTAMP > jwt_refresh_token_deadline_column).
        delete

      jwt_refresh_token_account_token_ds(account_id, token_id).
        get(jwt_refresh_token_key_column)
    end

    def jwt_refresh_token_account_ds(account_id)
      jwt_refresh_token_ds.where(jwt_refresh_token_account_id_column => account_id)
    end

    def jwt_refresh_token_account_token_ds(account_id, token_id)
      jwt_refresh_token_account_ds(account_id).
        where(jwt_refresh_token_id_column=>token_id)
    end

    def jwt_refresh_token_ds
      db[jwt_refresh_token_table]
    end

    def remove_jwt_refresh_token_key(token)
      account_id, token_id, _ = _account_refresh_token_split(token)
      jwt_refresh_token_account_token_ds(account_id, token_id).delete
    end

    def generate_refresh_token
      hash = jwt_refresh_token_insert_hash
      [account_id, jwt_refresh_token_ds.insert(hash), convert_token_key(hash[jwt_refresh_token_key_column])].join(token_separator)
    end

    def jwt_refresh_token_insert_hash
      hash = {jwt_refresh_token_account_id_column => account_id, jwt_refresh_token_key_column => random_key}
      set_deadline_value(hash, jwt_refresh_token_deadline_column, jwt_refresh_token_deadline_interval)
      hash
    end

    def set_jwt_refresh_token_hmac_session_key(token)
      if allow_refresh_with_expired_jwt_access_token?
        key = _account_refresh_token_split(token).last
        data = random_key
        set_session_value(jwt_refresh_token_data_session_key, data)
        set_session_value(jwt_refresh_token_hmac_session_key, compute_hmac(data + key))
      end
    end

    def before_logout
      if token = param_or_nil(jwt_refresh_token_key_param)
        if token == 'all'
          jwt_refresh_token_account_ds(session_value).delete
        else
          id, token_id, key = _account_refresh_token_split(token)

          if id && token_id && key && (actual = get_active_refresh_token(session_value, token_id)) && timing_safe_eql?(key, convert_token_key(actual))
            jwt_refresh_token_account_token_ds(id, token_id).delete
          end
        end
      end
      super if defined?(super)
    end

    def after_close_account
      jwt_refresh_token_account_ds(account_id).delete
      super if defined?(super)
    end
  end
end
