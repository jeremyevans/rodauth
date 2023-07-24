require_relative 'spec_helper'

begin
  require 'webauthn/fake_client'
rescue LoadError
else
describe 'Rodauth webauthn_autofill feature' do
  it "should handle autofill on login via WebAuthn" do
    rodauth do
      enable :logout, :webauthn_autofill, :create_account
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
    challenge = JSON.parse(page.find('#webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'Password', :with=>'0123456789'
    fill_in 'webauthn_setup', :with=>webauthn_client.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via password and webauthn'

    logout

    visit '/login'
    page.find("#login")[:autocomplete].must_equal "email webauthn"
    challenge = JSON.parse(page.find('#webauthn-login-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#notice_flash').text.must_equal "You have been logged in"
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via webauthn'

    logout

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    challenge = JSON.parse(page.find('#webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via webauthn'

    logout

    DB[:account_webauthn_keys].delete
    visit '/login'
    challenge = JSON.parse(page.find('#webauthn-login-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#error_flash').text.must_equal "There was an error authenticating via WebAuthn"
    page.current_path.must_equal '/login'

    visit '/webauthn-autofill-js'
    page.body.must_include File.binread("javascript/webauthn_autofill.js")

    visit '/create-account'
    page.find("#login")[:autocomplete].must_equal "email"
  end

  it "should allow webauthn autofill via json" do
    rodauth do
      enable :webauthn_autofill, :logout
      hmac_secret '123'
    end
    first_request = nil
    roda(:json) do |r|
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

    res = json_request('/webauthn-login', :login=>'foo@example.com')
    res[1]["webauthn_auth"]["allowCredentials"].wont_equal []

    res = json_request('/webauthn-login')
    auth_json = res[1].delete("webauthn_auth")
    challenge = res[1].delete("webauthn_auth_challenge")
    challenge_hmac = res[1].delete("webauthn_auth_challenge_hmac")
    res.must_equal [422, {"field-error"=>["webauthn_auth", "invalid webauthn authentication param"], "error"=>"There was an error authenticating via WebAuthn", "reason"=>"invalid_webauthn_auth_param"}]

    res = json_request('/webauthn-login', :webauthn_auth=>webauthn_client.get(challenge: auth_json['challenge']), :webauthn_auth_challenge=>challenge, :webauthn_auth_challenge_hmac=>challenge_hmac)
    res.must_equal [200, {'success'=>'You have been logged in'}]
    json_request.must_equal [200, ['webauthn']]
  end

  it "should support webauthn autofill using internal requests" do
    rodauth do
      enable :webauthn_autofill, :internal_request
      hmac_secret '123'
      domain "example.com"
    end
    roda do |r|
    end

    webauthn_client = WebAuthn::FakeClient.new("https://example.com")

    setup_params = app.rodauth.webauthn_setup_params(account_login: 'foo@example.com')
    app.rodauth.webauthn_setup(
      account_login: 'foo@example.com',
      webauthn_setup: webauthn_client.create(challenge: setup_params[:webauthn_setup][:challenge]),
      webauthn_setup_challenge: setup_params[:webauthn_setup_challenge],
      webauthn_setup_challenge_hmac: setup_params[:webauthn_setup_challenge_hmac]
    ).must_be_nil

    auth_params = app.rodauth.webauthn_login_params
    app.rodauth.webauthn_login(
      webauthn_auth: webauthn_client.get(challenge: auth_params[:webauthn_auth][:challenge]),
      webauthn_auth_challenge: auth_params[:webauthn_auth_challenge],
      webauthn_auth_challenge_hmac: auth_params[:webauthn_auth_challenge_hmac]
    ).must_equal DB[:accounts].get(:id)

    proc do
      app.rodauth.webauthn_login_params(login: 'bar@example.com')
    end.must_raise Rodauth::InternalRequestError
  end
end
end
