require_relative 'spec_helper'

require 'rotp'

describe 'Rodauth otp_modify_email feature' do
  secret_length = (ROTP::Base32.respond_to?(:random_base32) ? ROTP::Base32.random_base32 : ROTP::Base32.random).length

  it "should email when otp authentication is setup or disabled" do
    rodauth do
      enable :login, :otp_modify_email
      hmac_secret '123'
    end
    roda do |r|
      r.rodauth
      ""
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
