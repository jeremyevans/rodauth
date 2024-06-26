require_relative 'spec_helper'

require 'rotp'

describe 'Rodauth otp_lockout_email feature' do
  secret_length = (ROTP::Base32.respond_to?(:random_base32) ? ROTP::Base32.random_base32 : ROTP::Base32.random).length

  def reset_otp_last_use
    DB[:account_otp_keys].update(:last_use=>Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, :seconds=>600))
  end
  def reset_otp_unlock_next_attempt_after
    DB[:account_otp_unlocks].update(:next_auth_attempt_after=>Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, :seconds=>1))
  end

  it "should email when otp authentication is locked out, unlocked, or has a failed unlock attempt" do
    send_email = true
    rodauth do
      enable :login, :logout, :otp_lockout_email
      send_otp_locked_out_email?{send_email}
      send_otp_unlocked_email?{send_email}
      send_otp_unlock_failed_email?{send_email}
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

    reset_otp_last_use

    logout
    login

    6.times do
      page.title.must_equal 'Enter Authentication Code'
      fill_in 'Authentication Code', :with=>'foo'
      click_button 'Authenticate Using TOTP'
    end
    email = email_sent
    email.subject.must_equal "TOTP Authentication Locked Out"
    email.body.to_s.must_equal <<EMAIL
TOTP authentication has been locked out on your account due to too many
consecutive authentication failures. You can attempt to unlock TOTP
authentication for your account by consecutively authenticating via
TOTP multiple times.

If you did not initiate the TOTP authentication failures that
caused TOTP authentication to be locked out, that means someone already
has partial access to your account, but is unable to use TOTP
authentication to fully authenticate themselves.
EMAIL

    reset_otp_unlock_next_attempt_after
    visit page.current_path
    fill_in 'Authentication Code', :with=>'1'
    click_button 'Authenticate Using TOTP to Unlock'
    email = email_sent
    email.subject.must_equal "TOTP Authentication Unlocking Failed"
    email.body.to_s.must_equal <<EMAIL
Someone (hopefully you) attempted to unlock TOTP authentication for the
account associated to this email address, but failed as the
authentication code submitted was not correct.

If you did not initiate the TOTP authentication failure that generated
this email, that means someone already has partial access to your
account, but is unable to use TOTP authentication to fully authenticate
themselves.
EMAIL

    reset_otp_unlock_next_attempt_after
    visit page.current_path
    2.times do |i|
      fill_in 'Authentication Code', :with=>totp.now
      click_button 'Authenticate Using TOTP to Unlock'
      reset_otp_unlock_next_attempt_after
      visit page.current_path
    end

    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate Using TOTP to Unlock'
    email = email_sent
    email.subject.must_equal "TOTP Authentication Unlocked"
    email.body.to_s.must_equal <<EMAIL
Someone (hopefully you) has unlocked TOTP authentication for the account
associated to this email address.
EMAIL

    send_email = false
    visit '/otp-auth'

    6.times do
      page.title.must_equal 'Enter Authentication Code'
      fill_in 'Authentication Code', :with=>'foo'
      click_button 'Authenticate Using TOTP'
    end

    reset_otp_unlock_next_attempt_after
    visit page.current_path
    fill_in 'Authentication Code', :with=>'1'
    click_button 'Authenticate Using TOTP to Unlock'

    reset_otp_unlock_next_attempt_after
    visit page.current_path
    2.times do |i|
      fill_in 'Authentication Code', :with=>totp.now
      click_button 'Authenticate Using TOTP to Unlock'
      reset_otp_unlock_next_attempt_after
      visit page.current_path
    end

    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate Using TOTP to Unlock'
    Mail::TestMailer.deliveries.must_be_empty
  end
end
