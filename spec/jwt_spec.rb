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

    env = {"REQUEST_METHOD" => "POST",
           "PATH_INFO" => '/',
           "SCRIPT_NAME" => "",
           "CONTENT_TYPE" => "application/json",
           "SERVER_NAME" => 'example.com',
           "HTTP_AUTHORIZATION" => "Basic foo",
           "rack.input"=>StringIO.new('{}')
    }
    JSON.parse(@app.call(env.dup)[2].first).must_equal("error"=>"Please login to continue")

    env["HTTP_AUTHORIZATION"] = 'Digest foo'
    JSON.parse(@app.call(env.dup)[2].first).must_equal("error"=>"Please login to continue")
  end

  it "should only assume a json request if content-type is json if not in json only mode" do
    @no_freeze = true
    rodauth do
      enable :login, :logout, :jwt
      jwt_secret '1'
      json_response_success_key 'success'
    end
    roda do |r|
      r.rodauth
    end
    app.opts[:rodauth_json] = false

    res = json_request("/login", :content_type=>'application/x-www-form-urlencoded', :include_headers=>true, :method=>'GET')
    msg = "Only JSON format requests are allowed"
    res[1].delete('Set-Cookie')
    res.must_equal [400, {"Content-Type"=>'text/html', "Content-Length"=>msg.length.to_s}, [msg]]
  end
end
