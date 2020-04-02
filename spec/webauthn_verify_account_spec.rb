require_relative 'spec_helper'

begin
  require 'webauthn/fake_client'
rescue LoadError
else
describe 'Rodauth webauthn_verify_account feature' do
  it "should support setting up webauthn when verifying accounts" do
    rodauth do
      enable :webauthn_verify_account, :logout, :webauthn_login
      hmac_secret '123'
    end
    first_request = nil
    roda do |r|
      first_request ||= r
      r.rodauth
      r.root{view :content=>rodauth.authenticated_by ? "Logged In via #{rodauth.authenticated_by.join(' and ')}" : 'Not Logged In'}
    end

    visit '/create-account'
    origin = first_request.base_url
    webauthn_client = WebAuthn::FakeClient.new(origin)

    page.html.wont_include 'Password'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    page.html.must_include 'Not Logged In'
    page.current_path.must_equal '/'

    link = email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')

    visit link
    page.title.must_equal 'Setup WebAuthn Authentication'
    page.html.wont_include 'Password'
    click_button 'Setup WebAuthn Authentication'
    page.find('#error_flash').text.must_equal 'Unable to verify account'

    challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_setup', :with=>webauthn_client.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#notice_flash').text.must_equal "Your account has been verified"
    page.html.must_include 'Logged In via webauthn'
    page.current_path.must_equal '/'

    logout

    visit '/login'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Login'
    challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged In via webauthn'
  end

  it "should allow webauthn setup when verifying accounts via jwt" do
    rodauth do
      enable :webauthn_verify_account, :logout, :webauthn_login
      verify_account_email_body{verify_account_email_link}
      hmac_secret '123'
    end
    first_request = nil
    roda(:jwt) do |r|
      first_request ||= r
      r.rodauth
      rodauth.authenticated_by || ['']
    end

    res = json_request('/create-account', :login=>'foo@example2.com', :password=>'0123456789', "password-confirm"=>'0123456789')
    res.must_equal [200, {'success'=>"An email has been sent to you with a link to verify your account"}]
    link = email_link(/key=.+$/, 'foo@example2.com')

    origin = first_request.base_url
    webauthn_client = WebAuthn::FakeClient.new(origin)

    res = json_request('/verify-account', :key=>link[4..-1])
    setup_json = res[1].delete("webauthn_setup")
    challenge = res[1].delete("webauthn_setup_challenge")
    challenge_hmac = res[1].delete("webauthn_setup_challenge_hmac")
    res.must_equal [422, {"field-error"=>["webauthn_setup", "invalid webauthn setup param"], "error"=>"Unable to verify account"}]

    res = json_request('/verify-account', :key=>link[4..-1], :webauthn_setup=>webauthn_client.create(challenge: setup_json['challenge']), :webauthn_setup_challenge=>challenge, :webauthn_setup_challenge_hmac=>challenge_hmac)
    res.must_equal [200, {"success"=>"Your account has been verified"}]

    res = json_request('/webauthn-login', :login=>'foo@example2.com')
    auth_json = res[1].delete("webauthn_auth")
    challenge = res[1].delete("webauthn_auth_challenge")
    challenge_hmac = res[1].delete("webauthn_auth_challenge_hmac")
    res.must_equal [422, {"field-error"=>["webauthn_auth", "invalid webauthn authentication param"], "error"=>"There was an error authenticating via WebAuthn"}]

    res = json_request('/webauthn-login', :login=>'foo@example2.com', :webauthn_auth=>webauthn_client.get(challenge: auth_json['challenge']), :webauthn_auth_challenge=>challenge, :webauthn_auth_challenge_hmac=>challenge_hmac)
    res.must_equal [200, {'success'=>'You have been logged in'}]
    json_request.must_equal [200, ['webauthn']]
  end
end
end
