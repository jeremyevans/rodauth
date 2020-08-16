require_relative 'spec_helper'

describe 'Rodauth login feature' do
  it "should not have jwt refresh feature assume JWT token given during Basic/Digest authentication" do
    rodauth do
      enable :login, :logout, :jwt_refresh
    end
    roda(:jwt) do |r|
      rodauth.require_authentication
      '1'
    end

    res = json_request("/jwt-refresh", :headers=>{'HTTP_AUTHORIZATION'=>'Basic foo'})
    res.must_equal [401, {'error'=>'Please login to continue'}]

    res = json_request("/", :headers=>{'HTTP_AUTHORIZATION'=>'Digest foo'})
    res.must_equal [401, {'error'=>'Please login to continue'}]
  end

  it "should require json request content type in only json mode for rodauth endpoints only" do
    oj = false
    rodauth do
      enable :login, :logout, :jwt_refresh
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

    res = json_request("/", :content_type=>'application/x-www-form-urlencoded', :include_headers=>true, :method=>'GET')
    res[1].delete('Set-Cookie')
    res.must_equal [302, {"Content-Type"=>'text/html', "Content-Length"=>'0', "Location"=>"/login",}, []]

    res = json_request("/", :content_type=>'application/vnd.api+json', :method=>'GET')
    res.must_equal [400, ['{"error":"Please login to continue"}']]

    oj = true

    res = json_request("/", :content_type=>'application/x-www-form-urlencoded', :method=>'GET')
    res.must_equal [400, ['{"error":"Please login to continue"}']]

    res = json_request("/", :method=>'GET')
    res.must_equal [400, {'error'=>'Please login to continue'}]

    res = json_request("/login", :content_type=>'application/x-www-form-urlencoded', :include_headers=>true, :method=>'GET')
    msg = "Only JSON format requests are allowed"
    res[1].delete('Set-Cookie')
    res.must_equal [400, {"Content-Type"=>'text/html', "Content-Length"=>msg.length.to_s}, [msg]]

    jwt_refresh_login

    res = json_request("/", :content_type=>'application/x-www-form-urlencoded', :include_headers=>true, :method=>'GET')
    # res.must_equal [200, {"Content-Type"=>'text/html', "Content-Length"=>'1'}, ['1']]
  end

  it "should allow non-json requests if only_json? is false" do
    rodauth do
      enable :login, :logout, :jwt_refresh
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
      enable :login, :logout, :jwt_refresh
      jwt_secret '1'
      json_response_success_key 'success'
    end
    roda(:jwt) do |r|
      r.rodauth
    end

    res = json_request("/login", :method=>'GET')
    res.must_equal [405, {'error'=>'non-POST method used in JSON API'}]
  end

  it "should require Accept contain application/json if jwt_check_accept? is true and Accept is present" do
    rodauth do
      enable :login, :logout, :jwt_refresh
      jwt_secret '1'
      json_response_success_key 'success'
      jwt_check_accept? true
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

  it "should clear jwt refresh token when closing account" do
    rodauth do
      enable :login, :jwt_refresh, :close_account
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
      rodauth do
        enable :login, :logout, :jwt_refresh
        hmac_secret{secret} if hs
        jwt_secret '1'
      end
      roda(:jwt) do |r|
        r.rodauth
        rodauth.require_authentication
        response['Content-Type'] = 'application/json'
        {'hello' => 'world'}.to_json
      end
      res = json_request("/")
      res.must_equal [401, {'error'=>'Please login to continue'}]

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

      # Third refresh token is valid
      res = json_request("/jwt-refresh", :refresh_token=>third_refresh_token)
      jwt_refresh_validate(res)
      fourth_refresh_token = res.last['refresh_token']

      # And still gives us a valid access token
      @authorization = res.last['access_token']
      res = json_request("/")
      res.must_equal [200, {'hello'=>'world'}]

      if hs
        # Refresh secret doesn't work if hmac_secret changed
        secret = SecureRandom.random_bytes(32)
        res = json_request("/jwt-refresh", :refresh_token=>fourth_refresh_token)
        res.first.must_equal 400
        res.must_equal [400, {'error'=>'invalid JWT refresh token'}]

        # Refresh secret works if hmac_secret changed back
        secret = initial_secret
        res = json_request("/jwt-refresh", :refresh_token=>fourth_refresh_token)
        jwt_refresh_validate(res)

        # And still gives us a valid access token
        @authorization = res.last['access_token']
        res = json_request("/")
        res.must_equal [200, {'hello'=>'world'}]
      end
    end
  end

  it "prevents usage of previous access tokens after refresh when using active_sessions plugin" do
    rodauth do
      enable :login, :jwt_refresh, :active_sessions
      hmac_secret '123'
      jwt_secret '1'
    end
    roda(:jwt) do |r|
      r.rodauth
      rodauth.require_authentication
      rodauth.check_active_session
      response['Content-Type'] = 'application/json'
      {'hello' => 'world'}.to_json
    end
    res = json_request("/")
    res.must_equal [401, {'error'=>'Please login to continue'}]

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
    res.must_equal [401, {'error'=>'This session has been logged out'}]

    @authorization = post_refresh_access_token
    res = json_request("/")
    res.must_equal [200, {'hello'=>'world'}]
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
    res.must_equal [401, {"field-error"=>['password', 'invalid password'], "error"=>"There was an error logging in"}]
  end
end
