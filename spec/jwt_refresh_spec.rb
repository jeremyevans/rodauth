require_relative 'spec_helper'

describe 'Rodauth login feature' do
  it "should not have jwt refresh feature assume JWT token given during Basic/Digest authentication" do
    rodauth do
      enable :login, :jwt_refresh
    end
    roda(:jwt) do |r|
      rodauth.require_authentication
      '1'
    end

    res = json_request("/jwt-refresh", :headers=>{'HTTP_AUTHORIZATION'=>'Basic foo'})
    res.must_equal [401, {"reason"=>"login_required", 'error'=>'Please login to continue'}]

    res = json_request("/", :headers=>{'HTTP_AUTHORIZATION'=>'Digest foo'})
    res.must_equal [401, {"reason"=>"login_required", 'error'=>'Please login to continue'}]
  end

  it "should require json request content type in only json mode for rodauth endpoints only" do
    oj = false
    rodauth do
      enable :login, :jwt_refresh
      jwt_secret '1'
      json_response_success_key 'success'
      json_response_custom_error_status? false
      only_json?{oj}
    end
    roda(:csrf=>false, :json=>true) do |r|
      r.rodauth
      rodauth.require_authentication
      '1'
    end

    status, headers, body= json_request("/", :content_type=>'application/x-www-form-urlencoded', :include_headers=>true, :method=>'GET')
    status.must_equal 302
    headers['Set-Cookie'].must_be_kind_of String
    headers["Content-Type"].must_equal 'text/html'
    headers["Content-Length"].must_equal '0'
    headers["Location"].must_equal '/login'
    headers.length.must_equal 4
    body.must_equal ''

    res = json_request("/", :content_type=>'application/vnd.api+json', :method=>'GET')
    res.must_equal [400, '{"error":"Please login to continue"}']

    oj = true

    res = json_request("/", :content_type=>'application/x-www-form-urlencoded', :method=>'GET')
    res.must_equal [400, '{"error":"Please login to continue"}']

    res = json_request("/", :method=>'GET')
    res.must_equal [400, {'error'=>'Please login to continue'}]

    status, headers, body = json_request("/login", :content_type=>'application/x-www-form-urlencoded', :include_headers=>true, :method=>'GET')
    msg = "Only JSON format requests are allowed"
    status.must_equal 400
    headers["Content-Type"].must_equal 'text/html'
    headers["Content-Length"].must_equal msg.length.to_s
    headers.length.must_equal 2
    body.must_equal msg

    jwt_refresh_login

    status, headers, body = json_request("/", :content_type=>'application/x-www-form-urlencoded', :include_headers=>true, :method=>'GET')
    status.must_equal 200
    headers["Content-Type"].must_equal 'text/html'
    headers["Content-Length"].must_equal '1'
    headers.length.must_equal 2
    body.must_equal '1'
  end

  it "should allow non-json requests if only_json? is false" do
    rodauth do
      enable :login, :jwt_refresh
      jwt_secret '1'
      only_json? false
    end
    roda(:jwt_html) do |r|
      r.rodauth
      rodauth.require_authentication
      view(:content=>'1')
    end

    login
    page.find('#notice_flash').text.must_equal 'You have been logged in'
  end

  it "should require POST for json requests" do
    rodauth do
      enable :login, :jwt_refresh
      jwt_secret '1'
      json_response_success_key 'success'
    end
    roda(:jwt) do |r|
      r.rodauth
    end

    res = json_request("/login", :method=>'GET')
    res.must_equal [405, {'error'=>'non-POST method used in JSON API'}]
  end

  it "should require Accept contain application/json if json_check_accept? is true and Accept is present" do
    rodauth do
      enable :login, :jwt_refresh
      jwt_secret '1'
      json_response_success_key 'success'
      json_check_accept? true
    end
    roda(:jwt) do |r|
      r.rodauth
    end

    res = json_request("/login", :headers=>{'HTTP_ACCEPT'=>'text/html'})
    res.must_equal [406, {'error'=>'Unsupported Accept header. Must accept "application/json" or compatible content type'}]

    jwt_refresh_validate_login(json_request("/login", :login=>'foo@example.com', :password=>'0123456789'))
    jwt_refresh_validate_login(json_request("/login", :headers=>{'HTTP_ACCEPT'=>'*/*'}, :login=>'foo@example.com', :password=>'0123456789'))
    jwt_refresh_validate_login(json_request("/login", :headers=>{'HTTP_ACCEPT'=>'application/*'}, :login=>'foo@example.com', :password=>'0123456789'))
    jwt_refresh_validate_login(json_request("/login", :headers=>{'HTTP_ACCEPT'=>'application/vnd.api+json'}, :login=>'foo@example.com', :password=>'0123456789'))
  end

  [true, false].each do |before|
    it "should clear jwt refresh token when closing account, when loading jwt_refresh #{before ? "before" : "after"}" do
      rodauth do
        features = [:close_account, :jwt_refresh]
        features.reverse! if before
        enable :login, *features
        jwt_secret '1'
      end
      roda(:jwt) do |r|
        r.rodauth
        rodauth.require_authentication
        response['Content-Type'] = 'application/json'
        {'hello' => 'world'}.to_json
      end

      jwt_refresh_login

      DB[:account_jwt_refresh_keys].count.must_equal 1
      res = json_request('/close-account', :password=>'0123456789')
      res[1].delete('access_token').must_be_kind_of(String)
      res.must_equal [200, {'success'=>"Your account has been closed"}]
      DB[:account_jwt_refresh_keys].count.must_equal 0
    end
  end

  it "should set refresh tokens when creating accounts when using autologin" do
    rodauth do
      enable :login, :create_account, :jwt_refresh
      after_create_account{json_response[:account_id] = account_id}
      create_account_autologin? true
    end
    roda(:jwt) do |r|
      r.rodauth
      rodauth.require_authentication
      response['Content-Type'] = 'application/json'
      {'hello' => 'world'}.to_json
    end

    res = json_request('/create-account', :login=>'foo@example2.com', "login-confirm"=>'foo@example2.com', :password=>'0123456789', "password-confirm"=>'0123456789')
    refresh_token = res.last.delete('refresh_token')
    @authorization = res.last.delete('access_token')
    res.must_equal [200, {'success'=>"Your account has been created", 'account_id'=>DB[:accounts].where(:email=>'foo@example2.com').get(:id)}]

    res = json_request("/")
    res.must_equal [200, {'hello'=>'world'}]

    # We can refresh our token
    res = json_request("/jwt-refresh", :refresh_token=>refresh_token)
    jwt_refresh_validate(res)
    @authorization = res.last.delete('access_token')

    # Which we can use to access protected resources
    res = json_request("/")
    res.must_equal [200, {'hello'=>'world'}]
  end

  [false, true].each do |hs|
    it "generates and refreshes Refresh Tokens #{'with hmac_secret' if hs}" do
      initial_secret = secret = SecureRandom.random_bytes(32) if hs
      rt = nil
      rodauth do
        enable :login, :logout, :jwt_refresh
        hmac_secret{secret} if hs
        jwt_secret '1'
        skip_status_checks? hs
        after_refresh_token{rt = json_response['refresh_token']}
      end
      roda(:jwt) do |r|
        r.rodauth
        rodauth.require_authentication
        response['Content-Type'] = 'application/json'
        {'hello' => 'world'}.to_json
      end
      res = json_request("/")
      res.must_equal [401, {'reason'=>'login_required', 'error'=>'Please login to continue'}]

      # We can login
      res = jwt_refresh_login
      refresh_token = res.last['refresh_token']

      # Which gives us an access token which grants us access to protected resources
      @authorization = res.last['access_token']
      res = json_request("/")
      res.must_equal [200, {'hello'=>'world'}]

      # We can refresh our token
      res = json_request("/jwt-refresh", :refresh_token=>refresh_token)
      jwt_refresh_validate(res)
      second_refresh_token = res.last['refresh_token']
      second_refresh_token.must_equal rt

      # Which we can use to access protected resources
      @authorization = res.last['access_token']
      res = json_request("/")
      res.must_equal [200, {'hello'=>'world'}]

      # Subsequent refresh token is valid
      res = json_request("/jwt-refresh", :refresh_token=>second_refresh_token)
      jwt_refresh_validate(res)
      third_refresh_token = res.last['refresh_token']

      # First refresh token is now no longer valid
      res = json_request("/jwt-refresh", :refresh_token=>refresh_token)
      res.must_equal [400, {"error"=>"invalid JWT refresh token"}]

      # Test more invalid token types
      res = json_request("/jwt-refresh", :refresh_token=>refresh_token.gsub('_', '-'))
      res.must_equal [400, {"error"=>"invalid JWT refresh token"}]
      token_parts = refresh_token.split('_', 2)
      res = json_request("/jwt-refresh", :refresh_token=>"#{token_parts[0]}_#{token_parts[1].gsub('_', '-')}")
      res.must_equal [400, {"error"=>"invalid JWT refresh token"}]

      # Third refresh token is valid
      res = json_request("/jwt-refresh", :refresh_token=>third_refresh_token)
      jwt_refresh_validate(res)
      fourth_refresh_token = res.last['refresh_token']

      # And still gives us a valid access token
      @authorization = res.last['access_token']
      res = json_request("/")
      res.must_equal [200, {'hello'=>'world'}]

      # Disallow refresh token usage after logout
      json_request("/logout", :refresh_token=>fourth_refresh_token).first.must_equal 200
      fifth_refresh_token = jwt_refresh_login.last['refresh_token']
      json_request("/jwt-refresh", :refresh_token=>fourth_refresh_token).first.must_equal 400
      json_request("/logout", :refresh_token=>fifth_refresh_token[0...-1]).first.must_equal 200
      jwt_refresh_login
      json_request("/jwt-refresh", :refresh_token=>fifth_refresh_token).first.must_equal 200
      json_request("/logout", :refresh_token=>'all').first.must_equal 200
      sixth_refresh_token = jwt_refresh_login.last['refresh_token']
      json_request("/jwt-refresh", :refresh_token=>fifth_refresh_token).first.must_equal 400

      if hs
        # Refresh secret doesn't work if hmac_secret changed
        secret = SecureRandom.random_bytes(32)
        res = json_request("/jwt-refresh", :refresh_token=>sixth_refresh_token)
        res.first.must_equal 400
        res.must_equal [400, {'error'=>'invalid JWT refresh token'}]

        # Refresh secret works if hmac_secret changed back
        secret = initial_secret
        res = json_request("/jwt-refresh", :refresh_token=>sixth_refresh_token)
        jwt_refresh_validate(res)

        # And still gives us a valid access token
        @authorization = res.last['access_token']
        res = json_request("/")
        res.must_equal [200, {'hello'=>'world'}]
      end
    end
  end

  [true, false].each do |before|
    it "prevents usage of previous access tokens after refresh when using active_sessions plugin, when loading jwt_refresh #{before ? "before" : "after"}" do
      rodauth do
        features = [:active_sessions, :jwt_refresh]
        features.reverse! if before
        enable :login, *features, :logout
        hmac_secret '123'
        jwt_secret '1'
      end
      roda(:jwt) do |r|
        r.rodauth
        rodauth.require_authentication
        rodauth.check_active_session
        response['Content-Type'] = 'application/json'
        r.post('reset'){rodauth.session.delete(rodauth.session_id_session_key); rodauth.view(nil, nil)}
        {'hello' => 'world'}.to_json
      end
      res = json_request("/")
      res.must_equal [401, {'reason'=>'login_required', 'error'=>'Please login to continue'}]

      res = jwt_refresh_login
      refresh_token = res.last['refresh_token']
      @authorization = pre_refresh_access_token = res.last['access_token']

      res = json_request("/")
      res.must_equal [200, {'hello'=>'world'}]

      res = json_request("/jwt-refresh", :refresh_token=>refresh_token)
      jwt_refresh_validate(res)

      post_refresh_access_token = @authorization
      @authorization = pre_refresh_access_token
      res = json_request("/")
      res.must_equal [401, {'reason'=>'inactive_session', 'error'=>'This session has been logged out'}]

      @authorization = post_refresh_access_token
      res = json_request("/")
      res.must_equal [200, {'hello'=>'world'}]

      json_request("/logout")
      res = jwt_refresh_login
      refresh_token = res.last['refresh_token']
      json_request("/reset")
      res = json_request("/jwt-refresh", :refresh_token=>refresh_token)
      jwt_refresh_validate(res)
    end
  end

  it "should not return access_token for failed login attempt" do
    rodauth do
      enable :login, :create_account, :jwt_refresh
      after_create_account{json_response[:account_id] = account_id}
      create_account_autologin? true
    end
    roda(:jwt) do |r|
      r.rodauth
      rodauth.require_authentication
      response['Content-Type'] = 'application/json'
      {'hello' => 'world'}.to_json
    end

    json_request('/create-account', :login=>'foo@example2.com', "login-confirm"=>'foo@example2.com', :password=>'0123456789', "password-confirm"=>'0123456789')

    res = json_request('/login', :login=>'foo@example2.com', :password=>'123123')
    res.must_equal [401, {'reason'=>"invalid_password","field-error"=>['password', 'invalid password'], "error"=>"There was an error logging in"}]
  end

  it "should not allow refreshing token without providing access token" do
    rodauth do
      enable :login, :logout, :jwt_refresh, :close_account
      hmac_secret SecureRandom.random_bytes(32)
      jwt_secret '1'
    end
    roda(:jwt) do |r|
      r.rodauth
      rodauth.require_authentication
      response['Content-Type'] = 'application/json'
      {'authenticated_by' => rodauth.authenticated_by}.to_json
    end

    res = jwt_refresh_login
    @authorization = nil
    res = json_request("/jwt-refresh", :refresh_token=>res.last['refresh_token'])
    res.must_equal [401, {"error"=>"no JWT access token provided during refresh"}]

    json_request('/').must_equal [401, {"reason"=>"login_required", "error"=>"Please login to continue"}]
  end

  it "should not allow refreshing token when providing expired access token" do
    period = -2
    secret = '1'
    rodauth do
      enable :login, :logout, :jwt_refresh, :close_account
      jwt_secret{secret}
      jwt_access_token_period{period}
      expired_jwt_access_token_status 401
    end
    roda(:jwt) do |r|
      r.rodauth
      rodauth.require_authentication
      response['Content-Type'] = 'application/json'
      {'authenticated_by' => rodauth.authenticated_by}.to_json
    end

    res = jwt_refresh_login
    refresh_token = res.last['refresh_token']
    period = 1800

    res = json_request("/jwt-refresh", :refresh_token=>refresh_token)
    res.must_equal [401, {"error"=>"expired JWT access token"}]

    res = json_request('/')
    res.must_equal [401, {"error"=>"expired JWT access token"}]

    secret = '2'
    res = json_request('/')
    res.must_equal [400, {"error"=>"invalid JWT format or claim in Authorization header"}]
  end

  it "should allow refreshing token when providing expired access token if configured" do
    period = -2
    rodauth do
      enable :login, :logout, :jwt_refresh, :close_account
      hmac_secret SecureRandom.random_bytes(32)
      jwt_secret '1'
      jwt_access_token_period{period}
      allow_refresh_with_expired_jwt_access_token? true
    end
    roda(:jwt) do |r|
      r.rodauth
      rodauth.require_authentication
      response['Content-Type'] = 'application/json'
      {'authenticated_by' => rodauth.authenticated_by}.to_json
    end

    res = jwt_refresh_login
    refresh_token = res.last['refresh_token']
    period = 1800

    res = json_request("/jwt-refresh", :refresh_token=>refresh_token)
    jwt_refresh_validate(res)

    json_request('/').must_equal [200, {"authenticated_by"=>["password"]}]
  end

  it "should allow refreshing token when providing expired access token if configured and prefix is not correct" do
    period = -2
    rodauth do
      enable :login, :logout, :jwt_refresh, :close_account
      hmac_secret SecureRandom.random_bytes(32)
      jwt_secret '1'
      jwt_access_token_period{period}
      allow_refresh_with_expired_jwt_access_token? true
    end
    roda(:jwt) do |r|
      r.on 'auth' do
        r.rodauth
      end
      rodauth.require_authentication
      response['Content-Type'] = 'application/json'
      {'authenticated_by' => rodauth.authenticated_by}.to_json
    end

    res = jwt_refresh_login(:path=>'/auth/login')
    refresh_token = res.last['refresh_token']
    period = 1800

    res = json_request("/auth/jwt-refresh", :refresh_token=>refresh_token)
    jwt_refresh_validate(res)

    json_request('/').must_equal [200, {"authenticated_by"=>["password"]}]
  end

  it "should allow refreshing token when providing expired access token if configured with active_sessions" do
    period = -2
    rodauth do
      enable :active_sessions, :login, :logout, :jwt_refresh, :close_account
      hmac_secret SecureRandom.random_bytes(32)
      jwt_secret '1'
      jwt_access_token_period{period}
      allow_refresh_with_expired_jwt_access_token? true
    end
    roda(:jwt) do |r|
      rodauth.check_active_session
      r.rodauth
      rodauth.require_authentication
      response['Content-Type'] = 'application/json'
      {'authenticated_by' => rodauth.authenticated_by}.to_json
    end

    res = jwt_refresh_login
    refresh_token = res.last['refresh_token']
    period = 1800

    res = json_request("/jwt-refresh", :refresh_token=>refresh_token)
    jwt_refresh_validate(res)

    json_request('/').must_equal [200, {"authenticated_by"=>["password"]}]
  end

  it "should allow refreshing token for unverified accounts in grace period" do
    rodauth do
      enable :verify_account_grace_period, :login, :logout, :jwt_refresh
      hmac_secret SecureRandom.random_bytes(32)
      jwt_secret '1'
      require_password_confirmation? false
    end
    roda(:jwt_html) do |r|
      r.rodauth
      if rodauth.json_request?
        rodauth.require_authentication
        response['Content-Type'] = 'application/json'
        {'authenticated_by' => rodauth.authenticated_by}.to_json
      else
        r.root{view :content=>"Authenticated? #{!!rodauth.authenticated?}"}
      end
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'123456789'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')
    page.body.must_include('Authenticated? true')

    res = jwt_refresh_login(:login=>'foo@example2.com', :pass=>'123456789')
    refresh_token = res.last['refresh_token']

    res = json_request("/jwt-refresh", :refresh_token=>refresh_token)
    jwt_refresh_validate(res)

    json_request('/').must_equal [200, {"authenticated_by"=>["password"]}]
  end
end
