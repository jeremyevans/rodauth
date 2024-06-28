require_relative 'spec_helper'

require 'rotp'

describe 'Rodauth otp_lockout_email feature' do
  secret_length = (ROTP::Base32.respond_to?(:random_base32) ? ROTP::Base32.random_base32 : ROTP::Base32.random).length

  it "should email when otp authentication is locked out, unlocked, or has a failed unlock attempt" do
    rodauth do
      enable :login, :logout, :otp_modify_email
      hmac_secret '123'
    end
    roda do |r|
      r.rodauth

      r.redirect '/login' unless rodauth.logged_in?

      if rodauth.two_factor_authentication_setup?
        r.redirect '/otp-auth' unless rodauth.authenticated?
        view :content=>"With 2FA"
      else    
        view :content=>"Without 2FA"
      end
    end

    login
    visit '/otp-setup'
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup TOTP Authentication'
    email = email_sent
    email.subject.must_equal "TOTP Authentication Setup"
    email.body.to_s.must_equal <<EMAIL
Someone (hopefully you) has setup TOTP authentication for the account
associated to this email address.
EMAIL

    visit '/otp-disable'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Disable TOTP Authentication'
    email = email_sent
    email.subject.must_equal "TOTP Authentication Disabled"
    email.body.to_s.must_equal <<EMAIL
Someone (hopefully you) has disabled TOTP authentication for the account
associated to this email address.
EMAIL
  end
end
