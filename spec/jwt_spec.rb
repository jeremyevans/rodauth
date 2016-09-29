require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth login feature' do
  it "should not have jwt feature assume JWT token given during Basic/Digest authentication" do
    rodauth do
      enable :login, :logout
    end
    roda(:jwt) do |r|
      rodauth.require_authentication
      '1'
    end

    res = json_request("/", :headers=>{'HTTP_AUTHORIZATION'=>'Basic foo'})
    res.must_equal [400, {'error'=>'Please login to continue'}]

    res = json_request("/", :headers=>{'HTTP_AUTHORIZATION'=>'Digest foo'})
    res.must_equal [400, {'error'=>'Please login to continue'}]
  end

  it "should return error message if invalid JWT format used in request Authorization header" do
    rodauth do
      enable :login, :logout
    end
    roda(:jwt) do |r|
      r.rodauth
      rodauth.require_authentication
      '1'
    end

    res = json_request('/login', :include_headers=>true, :login=>'foo@example.com', :password=>'0123456789')

    res = json_request("/", :headers=>{'HTTP_AUTHORIZATION'=>res[1]['Authorization'][1..-1]})
    res.must_equal [400, {'error'=>'invalid JWT format in Authorization header'}]
  end

  it "should require json request content type in only json mode for rodauth endpoints only" do
    oj = false
    rodauth do
      enable :login, :logout, :jwt
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

    json_login

    res = json_request("/", :content_type=>'application/x-www-form-urlencoded', :include_headers=>true, :method=>'GET')
    res.must_equal [200, {"Content-Type"=>'text/html', "Content-Length"=>'1'}, ['1']]
  end

  it "should allow non-json requests if only_json? is false" do
    rodauth do
      enable :login, :logout, :jwt
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
      enable :login, :logout, :jwt
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
      enable :login, :logout, :jwt
      jwt_secret '1'
      json_response_success_key 'success'
      jwt_check_accept? true
    end
    roda(:jwt) do |r|
      r.rodauth
    end

    res = json_request("/login", :headers=>{'HTTP_ACCEPT'=>'text/html'})
    res.must_equal [406, {'error'=>'Unsupported Accept header. Must accept "application/json" or compatible content type'}]

    json_request("/login", :login=>'foo@example.com', :password=>'0123456789').must_equal [200, {"success"=>'You have been logged in'}]
    json_request("/login", :headers=>{'HTTP_ACCEPT'=>'*/*'}, :login=>'foo@example.com', :password=>'0123456789').must_equal [200, {"success"=>'You have been logged in'}]
    json_request("/login", :headers=>{'HTTP_ACCEPT'=>'application/*'}, :login=>'foo@example.com', :password=>'0123456789').must_equal [200, {"success"=>'You have been logged in'}]
    json_request("/login", :headers=>{'HTTP_ACCEPT'=>'application/vnd.api+json'}, :login=>'foo@example.com', :password=>'0123456789').must_equal [200, {"success"=>'You have been logged in'}]
  end

  it "generates and verifies JWTs with claims" do
    rodauth do
      enable :login, :logout, :jwt
      jwt_secret '1'
      json_response_success_key 'success'
      jwt_iss "Foobar, Inc."
      jwt_nbf proc { Time.now.to_i - 30 }
      jwt_exp proc { Time.now.to_i + 120 }
      jwt_jti proc { SecureRandom.uuid }
      jwt_aud %w[Young Old]
    end
    roda(:jwt) do |r|
      r.rodauth
      r.post { [1] }
    end

    json_login.must_equal [200, {"success"=>'You have been logged in'}]

    payload, _header = JWT.decode @authorization, nil, false
    payload['sub'].must_equal payload['data']['account_id']
    payload['iat'].must_be_kind_of Integer
    payload['exp'].must_be_kind_of Integer
    payload['nbf'].must_be_kind_of Integer
    payload['iss'].must_equal "Foobar, Inc."
    payload['aud'].must_equal %w[Young Old]
    payload['jti'].must_match(/^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-5][0-9a-f]{3}-?[089ab][0-9a-f]{3}-?[0-9a-f]{12}$/i)

    json_request.must_equal [200, [1]]
  end
end
