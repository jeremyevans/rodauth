require_relative 'spec_helper'

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
    res.must_equal [401, {'error'=>'Please login to continue'}]

    res = json_request("/", :headers=>{'HTTP_AUTHORIZATION'=>'Digest foo'})
    res.must_equal [401, {'error'=>'Please login to continue'}]
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
    res.must_equal [400, {'error'=>'invalid JWT format or claim in Authorization header'}]
  end

  it "should use custom JSON error statuses even if the request isn't in JSON format if a JWT is in use" do
    rodauth do
      only_json? true
    end
    roda(:jwt) do |r|
      r.rodauth
      rodauth.require_authentication
      '1'
    end

    status, headers, body = json_request("/", :headers=>{'CONTENT_TYPE'=>'text/html'}, :include_headers=>true)
    status.must_equal 401
    headers['Content-Type'].must_equal 'application/json'
    JSON.parse(body.join).must_equal("error"=>"Please login to continue")
  end

  it "should not check CSRF for json requests" do
    rodauth do
      enable :login, :jwt
      jwt_secret '1'
      only_json? false
    end
    roda(:jwt_html) do |r|
      r.rodauth
      view(:content=>'1')
    end

    res = json_request("/login", :login=>'foo@example.com', :password=>'0123456789', :csrf=>false).must_equal [200, {"success"=>'You have been logged in'}]
    res.must_equal true
  end

  it "should allow customizing JSON response bodies if invalid JWT format used in request Authorization header" do
    rodauth do
      enable :login, :logout, :jwt
      json_response_body do |hash|
        super('status'=>response.status, 'detail'=>hash)
      end
    end
    roda(:jwt) do |r|
      r.rodauth
      rodauth.require_authentication
      '1'
    end

    res = json_request('/login', :include_headers=>true, :login=>'foo@example.com', :password=>'0123456789')

    res = json_request("/", :headers=>{'HTTP_AUTHORIZATION'=>res[1]['Authorization'][1..-1]})
    res.must_equal [400, {'status'=>400, 'detail'=>{'error'=>'invalid JWT format or claim in Authorization header'}}]
  end

  it "should support valid_jwt? method for checking for valid JWT tokens" do
    rodauth do
      enable :login, :logout, :jwt
      jwt_secret '1'
      json_response_success_key 'success'
    end
    roda(:jwt) do |r|
      r.rodauth
      [rodauth.valid_jwt?.to_s]
    end

    res = json_request("/", :method=>'GET')
    res.must_equal [200, ['false']]

    res = json_request("/login", :method=>'GET')
    res.must_equal [405, {'error'=>'non-POST method used in JSON API'}]

    res = json_request("/", :method=>'GET')
    res.must_equal [200, ['true']]
  end

  it "should require Accept contain application/json if jwt_check_accept? is true and Accept is present" do
    warning = nil
    rodauth do
      enable :login, :logout, :jwt
      jwt_secret '1'
      json_response_success_key 'success'
      define_singleton_method(:warn) do |*a|
        warning = a.first
      end
      auth_class_eval do
        define_method(:warn) do |*a|
          warning = a.first
        end
        private :warn
      end
      jwt_check_accept? true
    end
    roda(:jwt) do |r|
      r.rodauth
    end

    res = json_request("/login", :headers=>{'HTTP_ACCEPT'=>'text/html'})
    res.must_equal [406, {'error'=>'Unsupported Accept header. Must accept "application/json" or compatible content type'}]
    warning.must_equal "Deprecated jwt_check_accept? method used during configuration, switch to using json_check_accept?"

    json_request("/login", :login=>'foo@example.com', :password=>'0123456789').must_equal [200, {"success"=>'You have been logged in'}]
    json_request("/login", :headers=>{'HTTP_ACCEPT'=>'*/*'}, :login=>'foo@example.com', :password=>'0123456789').must_equal [200, {"success"=>'You have been logged in'}]
    json_request("/login", :headers=>{'HTTP_ACCEPT'=>'application/*'}, :login=>'foo@example.com', :password=>'0123456789').must_equal [200, {"success"=>'You have been logged in'}]
    json_request("/login", :headers=>{'HTTP_ACCEPT'=>'application/vnd.api+json'}, :login=>'foo@example.com', :password=>'0123456789').must_equal [200, {"success"=>'You have been logged in'}]
  end

  it "generates and verifies JWTs with claims" do
    invalid_jti = false

    rodauth do
      enable :login, :logout, :jwt
      jwt_secret '1'
      json_response_success_key 'success'
      jwt_session_key 'data'
      jwt_symbolize_deeply? true
      jwt_session_hash do
        h = super()
        h['data']['foo'] = {:bar=>[1]}
        h.merge(
          :aud => %w[Young Old],
          :exp => Time.now.to_i + 120,
          :iat => Time.now.to_i,
          :iss => "Foobar, Inc.",
          :jti => SecureRandom.hex(10),
          :nbf => Time.now.to_i - 30,
          :sub => session_value
        )
      end
      jwt_decode_opts(
        :aud => 'Old',
        :iss => "Foobar, Inc.",
        :leeway => 30,
        :verify_aud => true,
        :verify_expiration => true,
        :verify_iat => true,
        :verify_iss => true,
        :verify_jti => proc{|jti| invalid_jti ? false : !!jti},
        :verify_not_before => true
      )
    end
    roda(:jwt) do |r|
      r.rodauth
      r.post{rodauth.session[:foo][:bar]}
    end

    json_login.must_equal [200, {"success"=>'You have been logged in'}]

    payload = JWT.decode(@authorization, nil, false)[0]
    payload['sub'].must_equal payload['data']['account_id']
    payload['iat'].must_be_kind_of Integer
    payload['exp'].must_be_kind_of Integer
    payload['nbf'].must_be_kind_of Integer
    payload['iss'].must_equal "Foobar, Inc."
    payload['aud'].must_equal %w[Young Old]
    payload['jti'].must_match(/^[0-9a-f]{20}$/)

    json_request.must_equal [200, [1]]

    invalid_jti = true
    json_login(:no_check=>true).must_equal [400, {"error"=>'invalid JWT format or claim in Authorization header'}]
  end

  it "handles case where there is no data in the session due to use of jwt_session_key" do
    key = 'data'
    rodauth do
      enable :login, :jwt
      jwt_secret '1'
      jwt_session_key{key}
      after_login do
        session[:foo] = 'bar'
      end
    end
    roda(:jwt) do |r|
      r.rodauth
      r.post{[rodauth.session[:foo], rodauth.valid_jwt?]}
    end

    json_login.must_equal [200, {"success"=>'You have been logged in'}]
    json_request[1].must_equal ['bar', true]
    key = 'data2'
    json_request[1].must_equal [nil, true]
  end

  it "should return empty JWT token after calling #clear_session" do
    rodauth do
      enable :login
    end
    roda(:jwt_html) do |r|
      r.rodauth
      r.post('clear') do
        rodauth.clear_session
        rodauth.session
      end
      r.post('') do
        rodauth.session
      end
    end

    json_login

    res = json_request '/clear', include_headers: true
    res[1]['Authorization'].wont_be_nil
    res[2].must_equal({})

    res = json_request '/'
    res[1].must_equal({})
  end
end
