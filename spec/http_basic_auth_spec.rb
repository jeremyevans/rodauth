require File.expand_path("spec_helper", File.dirname(__FILE__))

describe "Rodauth http basic auth feature" do
  def basic_auth_visit(opts={})
    page.driver.browser.basic_authorize(opts.fetch(:username,"foo@example.com"), opts.fetch(:password, "0123456789"))
    visit(opts.fetch(:path, '/'))
  end

  def authorization_header(opts={})
    ["#{opts.delete(:username)||'foo@example.com'}:#{opts.delete(:password)||'0123456789'}"].pack("m*")
  end

  def basic_auth_json_request(opts={})
    auth = opts.delete(:auth) || authorization_header(opts)
    path = opts.delete(:path) || '/'
    json_request(path, opts.merge(:headers => {"HTTP_AUTHORIZATION" => "Basic #{auth}"}, :method=>'GET'))
  end

  def newline_basic_auth_json_request(opts={})
    auth = opts.delete(:auth) || authorization_header(opts)
    auth.chomp!
    basic_auth_json_request(opts.merge(:auth => auth))
  end

  describe "on page visit" do
    before do
      rodauth do
        enable :http_basic_auth
      end
      roda do |r|
        r.rodauth
        r.root{view :content=>(rodauth.logged_in? ? "Logged In" : 'Not Logged')}
      end
    end

    it "handles logins" do
      basic_auth_visit
      page.text.must_include "Logged In"
    end

    it "keeps the user logged in" do
      visit '/'
      page.text.must_include "Not Logged"

      basic_auth_visit
      page.text.must_include "Logged In"

      visit '/'
      page.text.must_include "Logged In"
    end

    it "fails when no login is found" do
      basic_auth_visit(:username => "foo2@example.com")
      page.text.must_include "Not Logged"
      page.response_headers.keys.must_include("WWW-Authenticate")
    end

    it "fails when passowrd does not match" do
      basic_auth_visit(:password => "1111111111")
      page.text.must_include "Not Logged"
      page.response_headers.keys.must_include("WWW-Authenticate")
    end
  end

  it "works with standard authentication" do
    rodauth do
      enable :login, :http_basic_auth
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>(rodauth.logged_in? ? "Logged In" : 'Not Logged')}
    end

    login
    page.text.must_include "Logged In"
  end

  it "does not allow login to unverified account" do
    rodauth do
      enable :http_basic_auth
      skip_status_checks? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>(rodauth.logged_in? ? "Logged In" : 'Not Logged')}
    end
    DB[:accounts].update(:status_id=>1)

    basic_auth_visit
    page.text.must_include "Not Logged"
    page.response_headers.keys.must_include("WWW-Authenticate")
  end

  it "should login via jwt" do
    rodauth do
      enable :http_basic_auth
    end
    roda(:jwt) do |r|
      r.rodauth
      response['Content-Type'] = 'application/json'
      rodauth.require_authentication
      {"success"=>'You have been logged in'}
    end

    @authorization = nil
    res = basic_auth_json_request(:auth=>'.')
    res.must_equal [400, {'error'=>"Please login to continue"}]

    @authorization = nil
    res = basic_auth_json_request(:username=>'foo@example2.com')
    res.must_equal [401, {'error'=>"Please login to continue", "field-error"=>["login", "no matching login"]}]

    @authorization = nil
    res = basic_auth_json_request(:password=>'012345678')
    res.must_equal [401, {'error'=>"Please login to continue", "field-error"=>["password", "invalid password"]}]

    @authorization = nil
    res = newline_basic_auth_json_request
    res.must_equal [200, {"success"=>'You have been logged in'}]

    @authorization = nil
    res = basic_auth_json_request
    res.must_equal [200, {"success"=>'You have been logged in'}]
  end
end
