# frozen-string-literal: true

module Rodauth
  HTTTBasicAuth = Feature.define(:http_basic_auth) do
    auth_value_method :basic_auth_realm, "protected"

    def session

      return @session if defined?(@session)
      sess = super
      if !sess[session_key] && basic_auth?
        username, password = basic_credentials
        @session = if username && password
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
          sess
        end
      end
      sess
    end

    def throw_basic_auth_error(*args)
      response.status = 401
      response.headers["WWW-Authenticate"] = "Basic realm=#{basic_auth_realm}"
      throw_error(*args) 
    end

    private


    def basic_auth?
      return @basic_token if defined?(@basic_token)

      @basic_token = ((v = request.env['HTTP_AUTHORIZATION']) && v[/\A *Basic (.*)\n\z/, 1])
    end

    def basic_credentials
      return @basic_credentials if defined?(@basic_credentials)

      @basic_credentials = @basic_token.unpack("m*").first.split(/:/, 2)
    end
  end
end
