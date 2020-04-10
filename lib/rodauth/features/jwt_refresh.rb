# frozen-string-literal: true

module Rodauth
  Feature.define(:jwt_refresh, :JwtRefresh) do
    depends :jwt

    after 'refresh_token'
    before 'refresh_token'

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

    auth_private_methods(
      :account_from_refresh_token
    )

    route do |r|
      r.post do
        if (refresh_token = param_or_nil(jwt_refresh_token_key_param)) && account_from_refresh_token(refresh_token)
          formatted_token = nil
          transaction do
            before_refresh_token
            formatted_token = generate_refresh_token
            remove_jwt_refresh_token_key(refresh_token)
            after_refresh_token
          end
          json_response[jwt_refresh_token_key] = formatted_token
          json_response[jwt_access_token_key] = session_jwt
        else
          json_response[json_response_error_key] = jwt_refresh_invalid_token_message
          response.status ||= json_response_error_status
        end
        response['Content-Type'] ||= json_response_content_type
        response.write(_json_response_body(json_response))
        request.halt
      end
    end

    def update_session
      super

      # JWT login puts the access token in the header.
      # We put the refresh token in the body.
      # Note, do not put the access_token in the body here, as the access token content is not yet finalised.
      json_response['refresh_token'] = generate_refresh_token
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

    def _account_from_refresh_token(token)
      id, token = split_token(token)
      return unless id && token

      token_id, key = split_token(token)
      return unless token_id && key

      return unless actual = get_active_refresh_token(id, token_id)

      return unless timing_safe_eql?(key, convert_token_key(actual))

      ds = account_ds(id)
      ds = ds.where(account_status_column=>account_open_status_value) unless skip_status_checks?
      ds.first
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
      account_id, token = split_token(token)
      token_id, _ = split_token(token)
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

    def after_close_account
      jwt_refresh_token_account_ds(account_id).delete
      super if defined?(super)
    end
  end
end
