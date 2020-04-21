# frozen-string-literal: true

module Rodauth
  Feature.define(:http_basic_auth, :HttpBasicAuth) do
    auth_value_method :http_basic_auth_realm, "protected"
    auth_value_method :require_http_basic_auth?, false

    def require_login
      if !logged_in? && require_http_basic_auth?
        http_basic_auth

        unless logged_in?
          set_http_basic_auth_error_response
          request.halt
        end
      end

      super
    end

    def http_basic_auth
      return unless token = ((v = request.env['HTTP_AUTHORIZATION']) && v[/\A *Basic (.*)\Z/, 1])

      username, password = token.unpack("m*").first.split(/:/, 2)
      return unless username && password

      catch_error do
        unless account_from_login(username)
          throw_basic_auth_error(login_param, no_matching_login_message)
        end

        before_login_attempt

        unless open_account?
          throw_basic_auth_error(login_param, no_matching_login_message)
        end

        unless password_match?(password)
          after_login_failure
          throw_basic_auth_error(password_param, invalid_password_message)
        end

        transaction do
          before_login
          login_session('password')
          after_login
        end
      end
    end

    private

    def set_http_basic_auth_error_response
      response.status = 401
      response.headers["WWW-Authenticate"] = "Basic realm=\"#{http_basic_auth_realm}\""
    end

    def throw_basic_auth_error(*args)
      set_http_basic_auth_error_response
      throw_error(*args) 
    end
  end
end
