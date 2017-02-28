# frozen-string-literal: true

module Rodauth
  JwtRefresh = Feature.define(:jwt_refresh) do
    depends :jwt

    auth_value_method :access_token_period, 30*60
    auth_value_method :refresh_token_deadline_interval, {:days=>14}
    auth_value_method :refresh_token_deadline_column, :deadline
    auth_value_method :refresh_token_table, :account_refresh_tokens
    auth_value_method :refresh_token_id_column, :id
    auth_value_method :refresh_token_account_id_column, :account_id
    auth_value_method :refresh_token_key_column, :key
    auth_value_method :token_separator, '_'
    auth_value_method :refresh_token_key_param, 'refresh_token'
    auth_value_method :access_token_key, 'access_token'
    auth_value_method :refresh_token_key, 'refresh_token'
    auth_value_method :json_invalid_refresh_token, 'invalid refresh token'

    auth_methods(
      :after_login,
      :set_jwt_token,
      :jwt_session_hash,
      :before_refresh_token,
      :after_refresh_token
    )

    route do |r|
      r.post do
        refresh_token = param(refresh_token_key_param)
        if account_from_refresh_token(refresh_token)
          transaction do
            before_refresh_token
            get_refresh_token
            remove_refresh_token_key
            after_refresh_token
          end
          json_response[refresh_token_key]=format_refresh_token
          json_response[access_token_key]= session_jwt
        else
          json_response[json_response_error_key] = json_invalid_refresh_token
          response.status ||= json_response_error_status
        end
        response['Content-Type'] ||= json_response_content_type
        response.write(request.send(:convert_to_json, json_response))
        request.halt
      end
    end

    def after_login
      super
      # JWT login puts the token in the header.
      # We put the refresh token in the body.
      # Note, do not put the access_token in the body here, as the access token content is not yet finalised.
      json_response['refresh_token']= get_refresh_token
    end

    def set_jwt_token(token)
      super(token)
      json_response[access_token_key]= token
    end

    def jwt_session_hash
      h = super()
      h.merge(
          :exp => Time.now.to_i + access_token_period,
          :iat => Time.now.to_i,
          :nbf => Time.now.to_i - 5
      )
    end

    # User hooks
    def before_refresh_token
    end

    def after_refresh_token
    end

    private
    attr_reader :refresh_token_key_value, :used_token_id, :inserted_token_id

    def account_from_refresh_token(token)
      @account = _account_from_refresh_token(token)
    end

    def _account_from_refresh_token(token)
      account_from_key(token, account_open_status_value){|id| get_active_refresh_token_record(id)}
    end

    def get_active_refresh_token_record(id)
      active_refresh_token_ds(id)
    end

    def active_refresh_token_ds(id)
      refresh_token_ds_with_id(id).where(Sequel.expr(refresh_token_deadline_column) > Sequel::CURRENT_TIMESTAMP)
    end

    def refresh_token_ds_with_id(id)
      refresh_token_ds.where(refresh_token_id_column=>id)
    end

    def refresh_token_ds
      db[refresh_token_table]
    end

    def account_from_key(token, status_id=nil)
      id, key = split_token(token)
      return unless id && key
      record = yield(id)
      return unless actual = record.get(refresh_token_key_column)
      return unless timing_safe_eql?(key, actual)
      @used_token_id = id # We need to save the key to delete it later
      account = record.get(refresh_token_account_id_column)
      ds = account_ds(account)
      ds = ds.where(account_status_column=>status_id) if status_id && !skip_status_checks?
      ds.first
    end

    def remove_refresh_token_key
      refresh_token_ds_with_id(used_token_id).delete
    end

    def split_token(token)
      token.split(token_separator, 2)
    end

    def format_refresh_token
      "#{inserted_token_id}#{token_separator}#{refresh_token_key_value}"
    end

    def get_refresh_token
      generate_refresh_token_key_value
      transaction do
        create_refresh_token_key
      end
      format_refresh_token
    end

    def create_refresh_token_key
      ds = refresh_token_ds
      transaction do
        @inserted_token_id = ds.insert(refresh_token_insert_hash)
      end
    end

    def refresh_token_insert_hash
      hash = {
          # refresh_token_id_column=> id,
          refresh_token_account_id_column=> account_id,
          refresh_token_key_column=> refresh_token_key_value
      }
      set_deadline_value(hash, refresh_token_deadline_column, refresh_token_deadline_interval)
      hash
    end

    def after_close_account
      remove_refresh_token_key
      super if defined?(super)
    end

    def generate_refresh_token_key_value
      @refresh_token_key_value = random_key
    end

  end
end
