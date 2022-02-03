require_relative 'spec_helper'

describe 'Rodauth json feature' do
  it "should require json request content type in only json mode for rodauth endpoints only" do
    oj = false
    rodauth do
      enable :login, :logout, :json
      json_response_success_key 'success'
      json_response_custom_error_status? false
      only_json?{oj}
    end
    roda(:json=>true) do |r|
      r.rodauth
      rodauth.require_authentication
      '1'
    end

    status, headers, body = json_request("/", :content_type=>'application/x-www-form-urlencoded', :include_headers=>true, :method=>'GET')
    status.must_equal 302
    headers['Set-Cookie'].must_be_kind_of String
    headers["Content-Type"].must_equal 'text/html'
    headers["Content-Length"].must_equal '0'
    headers["Location"].must_equal '/login'
    headers.length.must_equal 4
    body.must_equal []

    res = json_request("/", :content_type=>'application/vnd.api+json', :method=>'GET')
    res.must_equal [400, ['{"error":"Please login to continue"}']]

    oj = true

    res = json_request("/", :content_type=>'application/x-www-form-urlencoded', :method=>'GET')
    res.must_equal [400, ['{"error":"Please login to continue"}']]

    res = json_request("/", :method=>'GET')
    res.must_equal [400, {'error'=>'Please login to continue'}]

    status, headers, body = json_request("/login", :content_type=>'application/x-www-form-urlencoded', :include_headers=>true, :method=>'GET')
    msg = "Only JSON format requests are allowed"
    status.must_equal 400
    headers["Content-Type"].must_equal 'text/html'
    headers["Content-Length"].must_equal msg.length.to_s
    headers.length.must_equal 2
    body.must_equal [msg]

    json_login

    status, headers, body = json_request("/", :content_type=>'application/x-www-form-urlencoded', :include_headers=>true, :method=>'GET')
    status.must_equal 200
    headers['Set-Cookie'].must_be_kind_of String
    headers["Content-Type"].must_equal 'text/html'
    headers["Content-Length"].must_equal '1'
    headers.length.must_equal 3
    body.must_equal ['1']
  end

  it "should allow non-json requests if only_json? is false" do
    rodauth do
      enable :login, :logout
    end
    roda(:json_html) do |r|
      r.rodauth
      rodauth.require_authentication
      view(:content=>'1')
    end

    login
    page.find('#notice_flash').text.must_equal 'You have been logged in'
  end

  it "should require POST for json requests" do
    rodauth do
      enable :login, :logout
      json_response_success_key 'success'
    end
    roda(:json) do |r|
      r.rodauth
    end

    res = json_request("/login", :method=>'GET')
    res.must_equal [405, {'error'=>'non-POST method used in JSON API'}]
  end

  it "should allow customizing JSON response bodies" do
    rodauth do
      enable :login, :logout
      json_response_body do |hash|
        super('status'=>response.status, 'detail'=>hash)
      end
    end
    roda(:json) do |r|
      r.rodauth
    end

    res = json_request("/login", :method=>'GET')
    res.must_equal [405, {'status'=>405, 'detail'=>{'error'=>'non-POST method used in JSON API'}}]
  end

  it "should require Accept contain application/json if json_check_accept? is true and Accept is present" do
    rodauth do
      enable :login, :logout
      json_response_success_key 'success'
      json_check_accept? true
    end
    roda(:json) do |r|
      r.rodauth
    end

    res = json_request("/login", :headers=>{'HTTP_ACCEPT'=>'text/html'})
    res.must_equal [406, {'error'=>'Unsupported Accept header. Must accept "application/json" or compatible content type'}]

    json_request("/login", :login=>'foo@example.com', :password=>'0123456789').must_equal [200, {"success"=>'You have been logged in'}]
    json_request("/login", :headers=>{'HTTP_ACCEPT'=>'*/*'}, :login=>'foo@example.com', :password=>'0123456789').must_equal [200, {"success"=>'You have been logged in'}]
    json_request("/login", :headers=>{'HTTP_ACCEPT'=>'application/*'}, :login=>'foo@example.com', :password=>'0123456789').must_equal [200, {"success"=>'You have been logged in'}]
    json_request("/login", :headers=>{'HTTP_ACCEPT'=>'application/vnd.api+json'}, :login=>'foo@example.com', :password=>'0123456789').must_equal [200, {"success"=>'You have been logged in'}]
  end

  it "should have field error and error flash work correctly when using json feature for non-json requests" do
    mpl = false
    rodauth do
      enable :login, :logout
      json_response_success_key nil
      use_multi_phase_login?{mpl}
    end
    roda(:json_html) do |r|
      r.rodauth
      next unless rodauth.logged_in?
      r.root{view :content=>"Logged In"}
    end

    login(:pass=>'012345678')
    page.find('#error_flash').text.must_equal 'There was an error logging in'
    page.html.must_include("invalid password")

    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.current_path.must_equal '/'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.html.must_include("Logged In")

    visit '/logout'
    page.title.must_equal 'Logout'

    mpl = true
    click_button 'Logout'
    page.find('#notice_flash').text.must_equal 'You have been logged out'
    page.current_path.must_equal '/login'

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    page.find('#notice_flash').text.must_equal 'Login recognized, please enter your password'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.html.must_include("Logged In")

    visit '/logout'
    page.title.must_equal 'Logout'
    click_button 'Logout'

    json_login(:no_check=>true).must_equal [200, {}]
    res = json_request('/login', :login=>'foo@example.com')
    res.must_equal [200, {}]
  end

  it "should work with internal requests if only_json? is true" do
    rodauth do
      enable :login, :create_account, :internal_request, :json
      only_json? true
    end
    roda(:json=>true) do |r|
      r.rodauth
    end
    app.rodauth.create_account(:login=>'bar@example.com', :password=>'secret')
    app.rodauth.valid_login_and_password?(:login=>'bar@example.com', :password=>'secret').must_equal true
  end
end
