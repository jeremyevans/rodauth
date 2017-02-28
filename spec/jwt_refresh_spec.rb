require File.expand_path("spec_helper", File.dirname(__FILE__))

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
    res.must_equal [400, {'error'=>'Please login to continue'}]

    res = json_request("/", :headers=>{'HTTP_AUTHORIZATION'=>'Digest foo'})
    res.must_equal [400, {'error'=>'Please login to continue'}]
  end

  it "should require json request content type in only json mode for rodauth endpoints only" do
    oj = false
    rodauth do
      enable :login, :logout, :jwt_refresh
      jwt_secret '1'
      json_response_success_key 'success'
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

    json_login_with_refresh

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

    json_validate_login(json_request("/login", :login=>'foo@example.com', :password=>'0123456789'))
    json_validate_login(json_request("/login", :headers=>{'HTTP_ACCEPT'=>'*/*'}, :login=>'foo@example.com', :password=>'0123456789'))
    json_validate_login(json_request("/login", :headers=>{'HTTP_ACCEPT'=>'application/*'}, :login=>'foo@example.com', :password=>'0123456789'))
    json_validate_login(json_request("/login", :headers=>{'HTTP_ACCEPT'=>'application/vnd.api+json'}, :login=>'foo@example.com', :password=>'0123456789'))
  end

  it "generates and refresh Refresh Tokens" do
    rodauth do
      enable :login, :logout, :jwt_refresh
      jwt_secret '1'
    end
    roda(:jwt) do |r|
      r.rodauth
      rodauth.require_authentication
      response['Content-Type'] = 'application/json'
      {'hello' => 'world'}.to_json
    end
    # res = json_request("/")
    # res.must_equal [400, {'error'=>'Please login to continue'}]

    # We can login
    res = json_login_with_refresh
    refresh_token = res.last['refresh_token']
    # Which gives us an access token which grants us access to protected resources
    @authorization= res.last['access_token']
    res = json_request("/")
    res.must_equal [200, {'hello'=>'world'}]

    # We can refresh our token
    res = json_request("/jwt-refresh", :refresh_token=>refresh_token)
    json_validate_refresh(res)
    second_refresh_token = res.last['refresh_token']

    # Which we can use to access protected resources
    @authorization= res.last['access_token']
    res = json_request("/")
    res.must_equal [200, {'hello'=>'world'}]

    # Subsequent refresh token is valid
    res = json_request("/jwt-refresh", :refresh_token=>second_refresh_token)
    json_validate_refresh(res)
    third_refresh_token = res.last['refresh_token']

    # First refresh Token is now no longer valid
    res = json_request("/jwt-refresh", :refresh_token=>refresh_token)
    res.must_equal [400, {"error"=>"invalid refresh token"}]

    # Third refresh token is valid
    res = json_request("/jwt-refresh", :refresh_token=>third_refresh_token)
    json_validate_refresh(res)

    # And still gives us a valid access token
    @authorization= res.last['access_token']
    res = json_request("/")
    res.must_equal [200, {'hello'=>'world'}]
  end
end
