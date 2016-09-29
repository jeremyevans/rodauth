# frozen-string-literal: true

require 'jwt'

module Rodauth
  Jwt = Feature.define(:jwt) do
    auth_value_method :invalid_jwt_format_error_message, "invalid JWT format in Authorization header"
    auth_value_method :json_non_post_error_message, 'non-POST method used in JSON API'
    auth_value_method :json_not_accepted_error_message, 'Unsupported Accept header. Must accept "application/json" or compatible content type'
    auth_value_method :json_accept_regexp, /(?:(?:\*|\bapplication)\/\*|\bapplication\/(?:vnd\.api\+)?json\b)/i
    auth_value_method :json_request_content_type_regexp, /\bapplication\/(?:vnd\.api\+)?json\b/i
    auth_value_method :json_response_content_type, 'application/json'
    auth_value_method :json_response_error_status, 400
    auth_value_method :json_response_error_key, "error"
    auth_value_method :json_response_field_error_key, "field-error"
    auth_value_method :json_response_success_key, nil
    auth_value_method :jwt_algorithm, "HS256"
    auth_value_method :jwt_authorization_ignore, /\A(?:Basic|Digest) /
    auth_value_method :jwt_authorization_remove, /\ABearer:?\s+/
    auth_value_method :jwt_check_accept?, false
    auth_value_method :non_json_request_error_message, 'Only JSON format requests are allowed'

    auth_value_methods(
      :only_json?,
      :jwt_secret,
      :use_jwt?
    )

    # JWT claims and verifiers (see ruby-jwt for more info)
    auth_value_method :jwt_sub, proc { |ra| ra.session[ra.session_key] }
    auth_value_method :jwt_verify_sub?, false
    auth_value_method :jwt_iat, proc { Time.now.to_i }
    auth_value_method :jwt_verify_iat?, true
    auth_value_method :jwt_jti, nil
    auth_value_method :jwt_verify_jti?, false
    auth_value_method :jwt_leeway, 30

    %i[aud exp iss nbf].each do |reserved_claim|
      auth_value_method "jwt_#{reserved_claim}".to_sym, nil
      auth_value_method "jwt_verify_#{reserved_claim}?".to_sym, true
    end

    auth_methods(
      :json_request?,
      :jwt_token,
      :session_jwt,
      :set_jwt_token
    )

    def session
      return @session if defined?(@session)
      return super unless use_jwt?

      @session = if jwt_token && data = jwt_payload['data']
        JSON.parse(JSON.fast_generate(data), :symbolize_names=>true)
      else
        {}
      end
    end

    def clear_session
      super
      set_jwt if use_jwt?
    end

    def only_json?
      scope.class.opts[:rodauth_json] == :only
    end

    def set_field_error(field, message)
      return super unless use_jwt?
      json_response[json_response_field_error_key] = [field, message]
    end

    def set_error_flash(message)
      return super unless use_jwt?
      json_response[json_response_error_key] = message
    end

    def set_redirect_error_flash(message)
      return super unless use_jwt?
      json_response[json_response_error_key] = message
    end

    def set_notice_flash(message)
      return super unless use_jwt?
      json_response[json_response_success_key] = message if include_success_messages?
    end

    def set_notice_now_flash(message)
      return super unless use_jwt?
      json_response[json_response_success_key] = message if include_success_messages?
    end

    def session_jwt
      JWT.encode(jwt_claims.merge(:data=>session), jwt_secret, jwt_algorithm)
    end

    def jwt_claims
      claims = {}
      %i[aud exp iat iss jti nbf sub].each do |reserved_claim|
        next unless claim = send("jwt_#{reserved_claim}")

        claims[reserved_claim] =
          if claim.respond_to?(:call)
            claim.call(self)
          else
            claim
          end
      end
      claims
    end

    def jwt_verifiers
      verifiers = {}
      %i[aud exp iat iss jti nbf sub].each do |reserved_claim|
        # if there is no claim to verify or jwt_verify_foo? is falsy, we have nothing to do
        next unless send("jwt_#{reserved_claim}") && verifier = send("jwt_verify_#{reserved_claim}?")

        verifiers["verify_#{reserved_claim}".to_sym] = true

        # time-based verifiers do not require a comparison operand
        next if %i[exp iat nbf].include?(reserved_claim)

        if reserved_claim == :jti
          if verifier.respond_to?(:call) && (verifier = verifier.call(self)).respond_to?(:call)
            verifiers[reserved_claim] = verifier
            next
          end

          raise ArgumentError, 'JWT ID verifier must be callable (and return a callable)'
        end

        verifiers[reserved_claim] =
          if verifier.respond_to?(:call)
            verifier.call(self)
          elsif verifier == true
            send("jwt_#{reserved_claim}", self)
          else
            verifier
          end
      end
      verifiers[:leeway] = jwt_leeway if jwt_leeway
      verifiers
    end

    def jwt_token
      return @jwt_token if defined?(@jwt_token)

      if (v = request.env['HTTP_AUTHORIZATION']) && v !~ jwt_authorization_ignore
        @jwt_token = v.sub(jwt_authorization_remove, '')
      end
    end

    def set_jwt_token(token)
      response.headers['Authorization'] = token
    end

    private

    def before_rodauth
      if json_request?
        if jwt_check_accept? && (accept = request.env['HTTP_ACCEPT']) && accept !~ json_accept_regexp
          response.status = 406
          json_response[json_response_error_key] = json_not_accepted_error_message
          response['Content-Type'] ||= json_response_content_type
          response.write(request.send(:convert_to_json, json_response))
          request.halt
        end

        unless request.post?
          response.status = 405
          response.headers['Allow'] = 'POST'
          json_response[json_response_error_key] = json_non_post_error_message
          return_json_response
        end
      elsif only_json?
        response.status = json_response_error_status
        response.write non_json_request_error_message
        request.halt
      end

      super
    end

    def before_view_recovery_codes
      super if defined?(super)
      if json_request?
        json_response[:codes] = recovery_codes
        json_response[json_response_success_key] ||= "" if include_success_messages?
      end
    end

    def jwt_payload
      JWT.decode(jwt_token, jwt_secret, true, jwt_verifiers.merge(:algorithm=>jwt_algorithm))[0]
    rescue JWT::DecodeError
      json_response[json_response_error_key] = invalid_jwt_format_error_message
      response.status ||= json_response_error_status
      response['Content-Type'] ||= json_response_content_type
      response.write(request.send(:convert_to_json, json_response))
      request.halt
    end

    def jwt_secret
      raise ArgumentError, "jwt_secret not set"
    end

    def redirect(_)
      return super unless use_jwt?
      return_json_response
    end

    def include_success_messages?
      !json_response_success_key.nil?
    end

    def set_session_value(key, value)
      super
      set_jwt if use_jwt?
      value
    end

    def json_response
      @json_response ||= {}
    end

    def _view(meth, page)
      return super unless use_jwt?
      return super if meth == :render
      return_json_response
    end

    def return_json_response
      response.status ||= json_response_error_status if json_response[json_response_error_key]
      set_jwt
      response['Content-Type'] ||= json_response_content_type
      response.write(request.send(:convert_to_json, json_response))
      request.halt
    end

    def set_jwt
      set_jwt_token(session_jwt)
    end

    def json_request?
      return @json_request if defined?(@json_request)
      @json_request = request.content_type =~ json_request_content_type_regexp
    end

    def use_jwt?
      jwt_token || only_json? || json_request?
    end
  end
end
