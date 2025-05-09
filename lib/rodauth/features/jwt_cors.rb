# frozen-string-literal: true

module Rodauth
  Feature.define(:jwt_cors, :JwtCors) do
    depends :jwt

    auth_value_method :jwt_cors_allow_origin, false
    auth_value_method :jwt_cors_allow_methods, 'POST'
    auth_value_method :jwt_cors_allow_headers, 'Content-Type, Authorization, Accept'
    auth_value_method :jwt_cors_expose_headers, 'Authorization'
    auth_value_method :jwt_cors_max_age, 86400

    auth_methods(:jwt_cors_allow?)

    def jwt_cors_allow?
      return false unless origin = request.env['HTTP_ORIGIN']

      case allowed = jwt_cors_allow_origin
      when String
        timing_safe_eql?(origin, allowed)
      when Array
        allowed.any?{|s| timing_safe_eql?(origin, s)}
      when Regexp
        allowed =~ origin
      when true
        true
      else
        false
      end
    end

    private

    def before_rodauth
      if jwt_cors_allow?
        set_response_header('access-control-allow-origin', request.env['HTTP_ORIGIN'])

        # Handle CORS preflight request
        if request.request_method == 'OPTIONS'
          set_response_header('access-control-allow-methods', jwt_cors_allow_methods)
          set_response_header('access-control-allow-headers', jwt_cors_allow_headers)
          set_response_header('access-control-max-age', jwt_cors_max_age.to_s)
          response.status = 204
          return_response
        end

        set_response_header('access-control-expose-headers', jwt_cors_expose_headers)
      end

      super
    end
  end
end
