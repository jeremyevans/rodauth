require_relative 'spec_helper'

begin
  require 'webauthn/fake_client'
rescue LoadError
else
describe 'Rodauth webauthn feature' do
  it "should email when a webauth authenticator is added or removed" do
    rodauth do
      enable :login, :logout, :webauthn_modify_email
      hmac_secret '123'
      two_factor_modifications_require_password? false
      webauthn_remove_redirect '/foo'
    end
    first_request = nil
    roda do |r|
      first_request ||= r
      r.rodauth
      r.get('foo'){view :content=>"WebAuthn Removed"}
      rodauth.require_authentication
      rodauth.require_two_factor_setup
      view :content=>"With WebAuthn"
    end

    login
    origin = first_request.base_url

    webauthn_client = WebAuthn::FakeClient.new(origin)
    challenge = JSON.parse(page.find('#webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_setup', :with=>webauthn_client.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
    email = email_sent
    email.subject.must_equal "WebAuthn Authenticator Added"
    email.body.to_s.must_equal <<EMAIL
Someone (hopefully you) has added a WebAuthn authenticator to the
account associated to this email address. There are now 1 WebAuthn
authenticator(s) with access to the account.
EMAIL

    logout
    login

    challenge = JSON.parse(page.find('#webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>webauthn_client.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    page.current_path.must_equal '/'

    visit '/webauthn-remove'
    choose(/(?<=name="webauthn_remove" id=")webauthn-remove-[^"]*/.match(page.body)[0])
    click_button 'Remove WebAuthn Authenticator'
    page.find('#notice_flash').text.must_equal "WebAuthn authenticator has been removed"
    email = email_sent
    email.subject.must_equal "WebAuthn Authenticator Removed"
    email.body.to_s.must_equal <<EMAIL
Someone (hopefully you) has removed a WebAuthn authenticator from the
account associated to this email address. There are now 0 WebAuthn
authenticator(s) with access to the account.
EMAIL
  end
end
end
