require File.expand_path("spec_helper", File.dirname(__FILE__))
require 'uri'

describe "Rodauth http basic auth feature" do
  def basic_auth_visit(path, opts={} )
    page.driver.browser.basic_authorize(opts[:username], opts[:password])
    visit(path)
  end

  def basic_auth_json_request(path, opts={})
    auth = ["#{opts.delete(:username)}:#{opts.delete(:password)}"].pack("m*")
    json_request(path, opts.merge(headers: { "HTTP_AUTHORIZATION" => "Basic #{auth}"}))
  end

  describe "on page visit" do
    before do
      rodauth do
        enable :login, :http_basic_auth
      end
      roda do |r|
        r.rodauth
        rodauth.require_authentication
        r.root{view :content=>"Logged In"}
      end
    end
    it "handles logins" do
      # http-basic
      basic_auth_visit '/', username: "foo@example.com", password: "0123456789"
      page.text.must_include "Logged In"
    end

    it "keeps the user logged in" do
      visit '/'
      page.text.must_include "Please login to continue"

      basic_auth_visit '/', username: "foo@example.com", password: "0123456789"
      page.text.must_include "Logged In"

      visit '/'
      page.text.must_include "Logged In"

    end
    it "fails when no login is found" do
      # login not matched
      basic_auth_visit '/', username: "foo2@example.com", password: "0123456789"
      page.text.wont_include "Logged In"
      page.response_headers.keys.must_include("WWW-Authenticate")
    end
    it "fails when passowrd does not match" do
      # password not matched
      basic_auth_visit '/', username: "foo@example.com", password: "1111111111"
      page.text.wont_include "Logged In"
      page.response_headers.keys.must_include("WWW-Authenticate")

    end
  end
  it "works with standard authentication" do
    rodauth do
      enable :login, :http_basic_auth
    end
    roda do |r|
      r.rodauth
      rodauth.require_authentication
      r.root{view :content=>"Logged In"}
    end
    # standard authentication
    login username: "foo@example.com", password: "0123456789"
    page.text.must_include "Logged In"

  end

  it "does not allow login to unverified account" do
    rodauth do
      enable :login, :http_basic_auth
      skip_status_checks? false
    end
    roda do |r|
      r.rodauth
      rodauth.require_authentication
      r.root{view :content=>"Logged In"}
    end
    DB[:accounts].update(:status_id=>1)

    basic_auth_visit '/', username: "foo@example.com", password: "0123456789"
    page.text.wont_include "Logged In"
    page.response_headers.keys.must_include("WWW-Authenticate")
  end
  it "should login via jwt" do
    rodauth do
      enable :login, :http_basic_auth
      jwt_secret{proc{super()}.must_raise ArgumentError; "1"}
    end
    roda(:jwt) do |r|
      r.rodauth
      response['Content-Type'] = 'application/json'
      rodauth.require_authentication
      {"success"=>'You have been logged in'}
    end

    res = basic_auth_json_request("/", method: "GET")
    res.must_equal [401, {'error'=>"Please login to continue", "field-error"=>["login", "no matching login"]}]

    @authorization = nil
    res = basic_auth_json_request("/", method: "GET", :username=>'foo@example2.com', :password=>'0123456789')
    res.must_equal [401, {'error'=>"Please login to continue", "field-error"=>["login", "no matching login"]}]

    @authorization = nil
    res = basic_auth_json_request("/", method: "GET", :username=>'foo@example.com', :password=>'012345678')
    res.must_equal [401, {'error'=>"Please login to continue", "field-error"=>["password", "invalid password"]}]

    @authorization = nil
    basic_auth_json_request("/", method: "GET", :username=>'foo@example.com', :password=>'0123456789').must_equal [200, {"success"=>'You have been logged in'}]

  end
end
