# frozen-string-literal: true

module Rodauth
  Feature.define(:http_basic_auth, :HttpBasicAuth) do
    auth_value_method :http_basic_auth_realm, "protected"
    auth_value_method :require_http_basic_auth?, false

    def session
      return @session if defined?(@session)
      sess = super
      return sess if sess[session_key]
      return sess unless token = ((v = request.env['HTTP_AUTHORIZATION']) && v[/\A *Basic (.*)\Z/, 1])
      username, password = token.unpack("m*").first.split(/:/, 2)

      if username && password
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
            sess[session_key] = account_session_value
            after_login
          end
        end
      end

      sess
    end

    def require_login
      if !logged_in? && require_http_basic_auth?
        set_http_basic_auth_error_response
        request.halt
      end

      super
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
