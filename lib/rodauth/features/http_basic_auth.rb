# frozen-string-literal: true

module Rodauth
  Feature.define(:http_basic_auth, :HttpBasicAuth) do
    auth_value_method :http_basic_auth_realm, "protected"
    auth_value_method :require_http_basic_auth?, false

    def logged_in?
      ret = super

      if !ret && !defined?(@checked_http_basic_auth)
        http_basic_auth
        ret = super
      end

      ret
    end

    def require_login
      if require_http_basic_auth?
        require_http_basic_auth
      end

      super
    end

    def require_http_basic_auth
      unless http_basic_auth
        set_http_basic_auth_error_response
        return_response
      end
    end

    def http_basic_auth
      return @checked_http_basic_auth if defined?(@checked_http_basic_auth)

      @checked_http_basic_auth = nil
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

        @checked_http_basic_auth = true
        return true
      end

      nil
    end

    private

    def set_http_basic_auth_error_response
      response.status = 401
      set_response_header("www-authenticate", "Basic realm=\"#{http_basic_auth_realm}\"")
    end

    def throw_basic_auth_error(*args)
      set_http_basic_auth_error_response
      throw_error(*args) 
    end
  end
end
