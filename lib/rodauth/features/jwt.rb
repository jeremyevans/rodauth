# frozen-string-literal: true

require 'jwt'

module Rodauth
  Jwt = Feature.define(:jwt) do
    auth_value_method :json_non_post_error_message, 'non-POST method used in JSON API'
    auth_value_method :json_not_accepted_error_message, 'Unsupported Accept header. Must accept "application/json"'
    auth_value_method :json_request_content_type_regexp, /application\/json/i
    auth_value_method :json_response_content_type, 'application/json'
    auth_value_method :json_response_error_status, 400
    auth_value_method :json_response_error_key, "error"
    auth_value_method :json_response_field_error_key, "field-error"
    auth_value_method :json_response_success_key, nil
    auth_value_method :jwt_algorithm, "HS256"
    auth_value_method :jwt_check_accept?, false
    auth_value_method :non_json_request_error_message, 'Only JSON format requests are allowed'

    auth_value_methods(
      :only_json?,
      :jwt_secret,
      :use_jwt?
    )

    auth_methods(
      :json_request?,
      :jwt_token,
      :session_jwt,
      :set_jwt_token
    )

    def session
      return @session if defined?(@session)
      return super unless use_jwt?

      @session = if token = jwt_token
        s = {}
        payload, header = JWT.decode(token, jwt_secret, true, :algorithm=>jwt_algorithm)
        payload.each do |k,v|
          s[k.to_sym] = v
        end
        s
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
      JWT.encode(session, jwt_secret, jwt_algorithm)
    end

    def jwt_token
      return @jwt_token if defined?(@jwt_token)

      if (v = request.env['HTTP_AUTHORIZATION']) && v !~ /\A(?:Basic|Digest) /
        @jwt_token = v.sub(/\ABearer:?\s+/, '')
      end
    end

    def set_jwt_token(token)
      response.headers['Authorization'] = token
    end

    private

    def before_rodauth
      if json_request?
        if jwt_check_accept? && (accept = request.env['HTTP_ACCEPT']) && accept !~ json_request_content_type_regexp
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
