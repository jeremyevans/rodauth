# frozen-string-literal: true

require 'jwt'
require 'jwt/version'

module Rodauth
  Feature.define(:jwt, :Jwt) do
    depends :json

    translatable_method :invalid_jwt_format_error_message, "invalid JWT format or claim in Authorization header"
    auth_value_method :jwt_algorithm, "HS256"
    auth_value_method :jwt_authorization_ignore, /\A(?:Basic|Digest) /
    auth_value_method :jwt_authorization_remove, /\ABearer:?\s+/
    auth_value_method :jwt_decode_opts, {}.freeze
    auth_value_method :jwt_old_secret, nil
    auth_value_method :jwt_session_key, nil
    auth_value_method :jwt_symbolize_deeply?, false

    auth_value_methods(
      :jwt_secret,
      :use_jwt?
    )

    auth_methods(
      :jwt_session_hash,
      :jwt_token,
      :session_jwt,
      :set_jwt_token
    )

    def_deprecated_alias :json_check_accept?, :jwt_check_accept?

    def session
      return @session if defined?(@session)
      return super unless use_jwt?

      s = {}
      if jwt_token
        unless session_data = jwt_payload
          json_response[json_response_error_key] ||= invalid_jwt_format_error_message
          _return_json_response
        end

        if jwt_session_key
          session_data = session_data[jwt_session_key]
        end

        if session_data
          if jwt_symbolize_deeply?
            s = JSON.parse(JSON.generate(session_data), :symbolize_names=>true)
          elsif scope.opts[:sessions_convert_symbols]
            s = session_data
          else
            session_data.each{|k,v| s[k.to_sym] = v}
          end
        end
      end
      @session = s
    end

    def clear_session
      super
      set_jwt if use_jwt?
    end

    def jwt_secret
      raise ConfigurationError, "jwt_secret not set"
    end

    def jwt_session_hash
      jwt_session_key ? {jwt_session_key=>session} : session
    end

    def session_jwt
      JWT.encode(jwt_session_hash, jwt_secret, jwt_algorithm)
    end

    def jwt_token
      return @jwt_token if defined?(@jwt_token)

      if (v = request.env['HTTP_AUTHORIZATION']) && v !~ jwt_authorization_ignore
        @jwt_token = v.sub(jwt_authorization_remove, '')
      end
    end

    def set_jwt_token(token)
      set_response_header('authorization', token)
    end

    def use_jwt?
      use_json?
    end

    def use_json?
      jwt_token || super
    end

    def valid_jwt?
      !!(jwt_token && jwt_payload)
    end

    private

    def _jwt_decode_opts
      jwt_decode_opts
    end

    if JWT.gem_version >= Gem::Version.new("2.4")
      def _jwt_decode_secrets
        secrets = [jwt_secret, jwt_old_secret]
        secrets.compact!
        secrets
      end
    # :nocov:
    else
      def _jwt_decode_secrets
        jwt_secret
      end
    # :nocov:
    end

    def jwt_payload
      return @jwt_payload if defined?(@jwt_payload)
      @jwt_payload = JWT.decode(jwt_token, _jwt_decode_secrets, true, _jwt_decode_opts.merge(:algorithm=>jwt_algorithm))[0]
    rescue JWT::DecodeError => e
      rescue_jwt_payload(e)
    end

    def rescue_jwt_payload(_)
      @jwt_payload = false
    end

    def set_session_value(key, value)
      super
      set_jwt if use_jwt?
      value
    end

    def remove_session_value(key)
      value = super
      set_jwt if use_jwt?
      value
    end

    def return_json_response
      set_jwt
      super
    end

    def set_jwt
      set_jwt_token(session_jwt)
    end

    def use_scope_clear_session?
      super && !use_jwt?
    end
  end
end
