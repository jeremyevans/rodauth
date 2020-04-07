require_relative 'spec_helper'

begin
  require 'webauthn/fake_client'
rescue LoadError
else
describe 'Rodauth webauthn_login feature' do
  it "should handle logging in via webauthn authentication without password" do
    rodauth do
      enable :logout, :webauthn_login
      hmac_secret '123'
    end
    first_request = nil
    roda do |r|
      first_request ||= r
      r.rodauth

      if rodauth.logged_in?
        view :content=>"Logged In via #{rodauth.authenticated_by.join(' and ')}"
      else    
        view :content=>"Not Logged In"
      end
    end

    visit '/'
    page.html.must_include 'Not Logged In'

    origin = first_request.base_url
    webauthn_client = WebAuthn::FakeClient.new(origin)

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.html.must_include 'Logged In via password'

    visit '/webauthn-setup'
    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'Password', :with=>'0123456789'
    fill_in 'webauthn_setup', :with=>webauthn_client.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via password and webauthn'

    logout

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.html.must_include 'Logged In via password'

    logout

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client.get(challenge: challenge+'1').to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#error_flash').text.must_equal "There was an error authenticating via WebAuthn"
    page.current_path.must_equal '/login'

    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via webauthn'
  end

  it "should handle confirming password as second factor authentication after logging in via webauthn" do
    rodauth do
      enable :logout, :webauthn_login, :confirm_password
      hmac_secret '123'
    end
    first_request = nil
    roda do |r|
      first_request ||= r
      r.rodauth

      if rodauth.logged_in?
        view :content=>"Logged In via #{rodauth.authenticated_by.join(' and ')}"
      else    
        view :content=>"Not Logged In"
      end
    end

    visit '/'
    page.html.must_include 'Not Logged In'

    origin = first_request.base_url
    webauthn_client = WebAuthn::FakeClient.new(origin)

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.html.must_include 'Logged In via password'

    visit '/webauthn-setup'
    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'Password', :with=>'0123456789'
    fill_in 'webauthn_setup', :with=>webauthn_client.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via password and webauthn'

    logout

    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via webauthn'

    visit '/two-factor-auth'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Confirm Password'
    page.html.must_include 'Logged In via password and webauthn'
  end

  it "should handle regular two factor webauthn authentication after password authentication" do
    rodauth do
      enable :logout, :webauthn_login, :confirm_password
      hmac_secret '123'
    end
    first_request = nil
    roda do |r|
      first_request ||= r
      r.rodauth

      if rodauth.logged_in?
        view :content=>"Logged In via #{rodauth.authenticated_by.join(' and ')}"
      else    
        view :content=>"Not Logged In"
      end
    end

    visit '/'
    page.html.must_include 'Not Logged In'

    origin = first_request.base_url
    webauthn_client = WebAuthn::FakeClient.new(origin)

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.html.must_include 'Logged In via password'

    visit '/webauthn-setup'
    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'Password', :with=>'0123456789'
    fill_in 'webauthn_setup', :with=>webauthn_client.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via password and webauthn'

    logout

    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.html.must_include 'Logged In via password'

    visit '/webauthn-auth'
    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via password and webauthn'
  end

  it "should allow returning to requested location when login is required" do
    rodauth do
      enable :logout, :webauthn_login
      hmac_secret '123'
      login_return_to_requested_location? true
    end
    first_request = nil
    roda do |r|
      first_request ||= r
      r.rodauth

      r.root{view :content=>""}
      r.get('page') do
        rodauth.require_login
        view :content=>""
      end
    end

    visit '/'

    origin = first_request.base_url
    webauthn_client = WebAuthn::FakeClient.new(origin)

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'

    visit '/webauthn-setup'
    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'Password', :with=>'0123456789'
    fill_in 'webauthn_setup', :with=>webauthn_client.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'

    logout

    visit '/page'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
    page.current_path.must_equal '/page'
  end

  it "should allow adding and removing WebAuthn authenticators after logging in" do
    rodauth do
      enable :logout, :webauthn_login
      hmac_secret '123'
    end
    first_request = nil
    roda do |r|
      first_request ||= r
      r.rodauth

      if rodauth.logged_in?
        view :content=>"Logged In via #{rodauth.authenticated_by.join(' and ')}"
      else    
        view :content=>"Not Logged In"
      end
    end

    visit '/'
    page.html.must_include 'Not Logged In'

    origin = first_request.base_url
    webauthn_client1 = WebAuthn::FakeClient.new(origin)
    webauthn_client2 = WebAuthn::FakeClient.new(origin)

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.html.must_include 'Logged In via password'

    visit '/webauthn-setup'
    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'Password', :with=>'0123456789'
    fill_in 'webauthn_setup', :with=>webauthn_client1.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via password and webauthn'

    logout

    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    webauthn_hash1 = webauthn_client1.get(challenge: challenge)
    fill_in 'webauthn_auth', :with=>webauthn_hash1.to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via webauthn'

    visit '/webauthn-setup'
    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'Password', :with=>'0123456789'
    fill_in 'webauthn_setup', :with=>webauthn_client2.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via webauthn'

    logout

    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    webauthn_hash2 = webauthn_client2.get(challenge: challenge)
    fill_in 'webauthn_auth', :with=>webauthn_hash2.to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.html.must_include 'Logged In via webauthn'

    visit '/webauthn-remove'
    fill_in 'Password', :with=>'0123456789'
    choose "rodauth-webauthn-remove-#{webauthn_hash1["rawId"]}"
    click_button 'Remove WebAuthn Authenticator'
    page.find('#notice_flash').text.must_equal "WebAuthn authenticator has been removed"
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via webauthn'

    visit '/webauthn-remove'
    fill_in 'Password', :with=>'0123456789'
    choose "rodauth-webauthn-remove-#{webauthn_hash2["rawId"]}"
    click_button 'Remove WebAuthn Authenticator'
    page.find('#notice_flash').text.must_equal "WebAuthn authenticator has been removed"
    page.current_path.must_equal '/'
    page.html.must_include 'Not Logged In'

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.html.must_include 'Logged In via password'
  end

  it "should allow adding and removing WebAuthn authenticators after logging in if there is no password for account" do
    rodauth do
      enable :logout, :webauthn_login
      hmac_secret '123'
    end
    first_request = nil
    roda do |r|
      first_request ||= r
      r.rodauth

      if rodauth.logged_in?
        view :content=>"Logged In via #{rodauth.authenticated_by.join(' and ')}"
      else    
        view :content=>"Not Logged In"
      end
    end

    visit '/'
    page.html.must_include 'Not Logged In'

    origin = first_request.base_url
    webauthn_client1 = WebAuthn::FakeClient.new(origin)
    webauthn_client2 = WebAuthn::FakeClient.new(origin)

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.html.must_include 'Logged In via password'

    if ENV['RODAUTH_SEPARATE_SCHEMA']
      DB[Sequel[:rodauth_test_password][:account_password_hashes]].delete
    else
      DB[:account_password_hashes].delete
    end

    visit '/webauthn-setup'
    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_setup', :with=>webauthn_client1.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via password and webauthn'

    logout

    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    webauthn_hash1 = webauthn_client1.get(challenge: challenge)
    fill_in 'webauthn_auth', :with=>webauthn_hash1.to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via webauthn'

    visit '/webauthn-setup'
    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_setup', :with=>webauthn_client2.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via webauthn'

    logout

    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    webauthn_hash2 = webauthn_client2.get(challenge: challenge)
    fill_in 'webauthn_auth', :with=>webauthn_hash2.to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.html.must_include 'Logged In via webauthn'

    visit '/webauthn-remove'
    choose "rodauth-webauthn-remove-#{webauthn_hash1["rawId"]}"
    click_button 'Remove WebAuthn Authenticator'
    page.find('#notice_flash').text.must_equal "WebAuthn authenticator has been removed"
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via webauthn'

    visit '/webauthn-remove'
    choose "rodauth-webauthn-remove-#{webauthn_hash2["rawId"]}"
    click_button 'Remove WebAuthn Authenticator'
    page.find('#notice_flash').text.must_equal "WebAuthn authenticator has been removed"
    page.current_path.must_equal '/'
    page.html.must_include 'Not Logged In'
  end

  it "should allow webauthn login via jwt" do
    rodauth do
      enable :logout, :webauthn_login
      hmac_secret '123'
    end
    first_request = nil
    roda(:jwt) do |r|
      first_request ||= r
      r.rodauth
      rodauth.authenticated_by || ['']
    end

    json_request.must_equal [200, ['']]
    json_login
    json_request.must_equal [200, ['password']]

    origin = first_request.base_url
    webauthn_client = WebAuthn::FakeClient.new(origin)

    res = json_request('/webauthn-setup', :password=>'0123456789')
    setup_json = res[1].delete("webauthn_setup")
    challenge = res[1].delete("webauthn_setup_challenge")
    challenge_hmac = res[1].delete("webauthn_setup_challenge_hmac")
    webauthn_hash = webauthn_client.create(challenge: setup_json['challenge'])
    res = json_request('/webauthn-setup', :password=>'0123456789', :webauthn_setup=>webauthn_hash, :webauthn_setup_challenge=>challenge, :webauthn_setup_challenge_hmac=>challenge_hmac)
    res.must_equal [200, {'success'=>'WebAuthn authentication is now setup'}]

    json_logout
    json_request.must_equal [200, ['']]

    res = json_request('/webauthn-login')
    res.must_equal [401, {"field-error"=>["login", "no matching login"], "error"=>"There was an error authenticating via WebAuthn"}]

    res = json_request('/webauthn-login', :login=>'foo@example.com')
    auth_json = res[1].delete("webauthn_auth")
    challenge = res[1].delete("webauthn_auth_challenge")
    challenge_hmac = res[1].delete("webauthn_auth_challenge_hmac")
    res.must_equal [422, {"field-error"=>["webauthn_auth", "invalid webauthn authentication param"], "error"=>"There was an error authenticating via WebAuthn"}]

    res = json_request('/webauthn-login', :login=>'foo@example.com', :webauthn_auth=>webauthn_client.get(challenge: auth_json['challenge']), :webauthn_auth_challenge=>challenge, :webauthn_auth_challenge_hmac=>challenge_hmac)
    res.must_equal [200, {'success'=>'You have been logged in'}]
    json_request.must_equal [200, ['webauthn']]
  end
end
end

