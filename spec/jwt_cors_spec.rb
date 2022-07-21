require_relative 'spec_helper'

describe 'Rodauth jwt_cors feature' do
  it "should support CORS logins if allowed" do
    origin = false
    rodauth do
      enable :login, :jwt_cors
      jwt_secret '1'
      json_response_success_key 'success'
      jwt_cors_allow_origin{origin}
    end
    roda(:csrf=>false, :json=>true) do |r|
      r.rodauth
      rodauth.require_authentication
      response['Content-Type'] = 'application/json'
      '1'
    end

    # CORS Preflight Request
    preflight_request = {
      :method=>'OPTIONS',
      :headers=>{
        "HTTP_ACCESS_CONTROL_REQUEST_METHOD"=>"POST",
        "HTTP_ORIGIN"=>"https://foo.example.com",
        "HTTP_ACCESS_CONTROL_REQUEST_HEADERS"=>"content-type",
        "CONTENT_TYPE"=>' application/json'
      }
    }

    res = json_request("/login", preflight_request.dup)
    res.must_equal [405, "{\"error\":\"non-POST method used in JSON API\"}"]

    origin = Object.new
    res = json_request("/login", preflight_request.dup)
    res.must_equal [405, "{\"error\":\"non-POST method used in JSON API\"}"]

    req = preflight_request.dup
    req[:headers] = req[:headers].dup
    req[:headers].delete('HTTP_ORIGIN')
    res = json_request("/login", req)
    res.must_equal [405, "{\"error\":\"non-POST method used in JSON API\"}"]

    ["https://foo.example.com", ["https://foo.example.com"], %r{https://foo.example.com}, true].each do |orig|
      origin = orig

      res = json_request("/login", preflight_request.merge(:include_headers=>true))
      res[0].must_equal 204
      res[1]['Access-Control-Allow-Origin'].must_equal "https://foo.example.com"
      res[1]['Access-Control-Allow-Methods'].must_equal "POST"
      res[1]['Access-Control-Allow-Headers'].must_equal "Content-Type, Authorization, Accept"
      res[1]['Access-Control-Max-Age'].must_equal "86400"
      res[2].must_equal ""

      res = json_request("/login", :login=>'foo@example.com', :password=>'0123456789', :headers=>{"HTTP_ORIGIN"=>"https://foo.example.com"}, :include_headers=>true)
      res[0].must_equal 200
      res[1]['Access-Control-Allow-Origin'].must_equal "https://foo.example.com"
      res[1]['Access-Control-Expose-Headers'].must_equal "Authorization"
      res[2].must_equal("success"=>"You have been logged in")

      json_request("/foo").must_equal [200, 1]
    end
  end
end
