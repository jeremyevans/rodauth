require_relative 'spec_helper'

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

  it "should support HTTP basic authentication" do
    rodauth do
      enable :http_basic_auth
    end
    roda do |r|
      rodauth.http_basic_auth
      r.rodauth
      if rodauth.logged_in?
        view :content=>"Logged In via #{rodauth.authenticated_by.join(' and ')}"
      else
        view :content=>"Not Logged In"
      end
    end

    visit '/'
    page.text.must_include "Not Logged In"
    page.status_code.must_equal 200

    page.driver.browser.header("Authorization", "Bearer abc123")
    page.text.must_include "Not Logged In"
    page.status_code.must_equal 200

    basic_auth_visit(:username => "foo2@example.com")
    page.text.must_include "Not Logged In"
    page.response_headers.keys.must_include("WWW-Authenticate")
    page.status_code.must_equal 401
    page.text.must_include "Not Logged In"

    basic_auth_visit(:password => "1111111111")
    page.text.must_include "Not Logged In"
    page.response_headers.keys.must_include("WWW-Authenticate")
    page.status_code.must_equal 401
    page.text.must_include "Not Logged In"

    basic_auth_visit
    page.text.must_include "Logged In via password"
    page.status_code.must_equal 200

    visit '/'
    page.text.must_include "Logged In via password"
    page.status_code.must_equal 200
  end

  it "should support requiring HTTP basic authentication" do
    rodauth do
      enable :http_basic_auth
    end
    roda do |r|
      rodauth.require_http_basic_auth
      r.rodauth
      if rodauth.logged_in?
        view :content=>"Logged In via #{rodauth.authenticated_by.join(' and ')}"
      else
        view :content=>"Not Logged In"
      end
    end

    visit '/'
    page.response_headers.keys.must_include("WWW-Authenticate")
    page.status_code.must_equal 401
    page.html.must_equal ''

    basic_auth_visit
    page.text.must_include "Logged In via password"
    page.status_code.must_equal 200

    visit '/'
    page.text.must_include "Logged In via password"
    page.status_code.must_equal 200
  end

  it "requires HTTP basic authentication when require_http_basic_auth? is true" do
    rodauth do
      enable :http_basic_auth
      require_http_basic_auth? true
    end
    roda do |r|
      rodauth.require_authentication
      if rodauth.logged_in?
        view :content=>"Logged In via #{rodauth.authenticated_by.join(' and ')}"
      else
        view :content=>"Not Logged In"
      end
    end

    visit '/'
    page.status_code.must_equal 401
    page.response_headers.keys.must_include("WWW-Authenticate")

    basic_auth_visit
    page.text.must_include "Logged In via password"
  end

  it "should support re-authenticating without logging out" do
    rodauth do
      enable :http_basic_auth
      account_password_hash_column :ph
    end
    roda do |r|
      rodauth.http_basic_auth
      r.rodauth
      if rodauth.logged_in?
        view :content=>"Logged In as #{rodauth.account_from_session[:email]}"
      else
        view :content=>"Not Logged In"
      end
    end

    hash = BCrypt::Password.create('0123456789', :cost=>BCrypt::Engine::MIN_COST)
    DB[:accounts].insert(:email=>'bar@example.com', :status_id=>2, :ph=>hash)

    basic_auth_visit
    page.text.must_include "Logged In as foo@example.com"

    basic_auth_visit(username: "bar@example.com")
    page.text.must_include "Logged In as bar@example.com"

    visit "/"
    page.text.must_include "Logged In as bar@example.com"
  end

  it "works with standard authentication" do
    rodauth do
      enable :login, :http_basic_auth
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>(rodauth.logged_in? ? "Logged In" : 'Not Logged In')}
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
      rodauth.http_basic_auth
      r.rodauth
      r.root{view :content=>(rodauth.logged_in? ? "Logged In" : 'Not Logged In')}
    end
    DB[:accounts].update(:status_id=>1)

    basic_auth_visit
    page.text.must_include "Not Logged In"
    page.response_headers.keys.must_include("WWW-Authenticate")
  end

  it "should login via jwt" do
    rodauth do
      enable :http_basic_auth
    end
    roda(:jwt) do |r|
      rodauth.http_basic_auth
      r.rodauth
      response['Content-Type'] = 'application/json'
      rodauth.require_authentication
      {"success"=>'You have been logged in'}
    end

    @authorization = nil
    res = basic_auth_json_request(:auth=>'.')
    res.must_equal [401, {'error'=>"Please login to continue"}]

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
