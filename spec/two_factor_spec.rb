require_relative 'spec_helper'

require 'rotp'

describe 'Rodauth OTP feature' do
  secret_length = (ROTP::Base32.respond_to?(:random_base32) ? ROTP::Base32.random_base32 : ROTP::Base32.random).length

  def reset_otp_last_use
    DB[:account_otp_keys].update(:last_use=>Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, :seconds=>600))
  end

  it "should allow two factor authentication setup, login, recovery, removal" do
    sms_phone = sms_message = nil
    hmac_secret = '123'
    rodauth do
      enable :login, :logout, :otp, :recovery_codes, :sms_codes
      otp_drift 10
      hmac_secret do
        hmac_secret
      end
      sms_send do |phone, msg|
        proc{super(phone, msg)}.must_raise NotImplementedError
        sms_phone = phone
        sms_message = msg
      end
      auto_add_recovery_codes? true
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
    page.html.must_include('Without 2FA')

    %w'/otp-disable /recovery-auth /recovery-codes /sms-setup /sms-disable /sms-confirm /sms-request /sms-auth /otp-auth'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'This account has not been setup for two factor authentication'
      page.current_path.must_equal '/otp-setup'
    end

    page.title.must_equal 'Setup Two Factor Authentication'
    page.html.must_include '<svg' 
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'asdf'
    click_button 'Setup Two Factor Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up two factor authentication'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>"asdf"
    click_button 'Setup Two Factor Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up two factor authentication'
    page.html.must_include 'Invalid authentication code'

    hmac_secret = "321"
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up two factor authentication'

    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'With 2FA'

    logout
    login
    page.current_path.must_equal '/otp-auth'

    page.find_by_id('otp-auth-code')[:autocomplete].must_equal 'off'

    %w'/otp-disable /recovery-codes /otp-setup /sms-setup /sms-disable /sms-confirm'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'You need to authenticate via 2nd factor before continuing.'
      page.current_path.must_equal '/two-factor-auth'
    end

    page.title.must_equal 'Authenticate Using 2nd Factor'
    click_link 'Authenticate Using TOTP'
    page.title.must_equal 'Enter Authentication Code'
    fill_in 'Authentication Code', :with=>"asdf"
    click_button 'Authenticate via 2nd Factor'
    page.find('#error_flash').text.must_equal 'Error logging in via two factor authentication'
    page.html.must_include 'Invalid authentication code'

    fill_in 'Authentication Code', :with=>"#{totp.now[0..2]} #{totp.now[3..-1]}"
    click_button 'Authenticate via 2nd Factor'
    page.find('#error_flash').text.must_equal 'Error logging in via two factor authentication'
    page.html.must_include 'Invalid authentication code'
    reset_otp_last_use

    hmac_secret = '123'
    fill_in 'Authentication Code', :with=>"#{totp.now[0..2]} #{totp.now[3..-1]}"
    click_button 'Authenticate via 2nd Factor'
    page.find('#error_flash').text.must_equal 'Error logging in via two factor authentication'
    page.html.must_include 'Invalid authentication code'
    reset_otp_last_use

    hmac_secret = '321'
    fill_in 'Authentication Code', :with=>"#{totp.now[0..2]} #{totp.now[3..-1]}"
    click_button 'Authenticate via 2nd Factor'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
    page.html.must_include 'With 2FA'
    reset_otp_last_use

    visit '/otp-setup'
    page.find('#error_flash').text.must_equal 'You have already setup two factor authentication'

    %w'/otp-auth /recovery-auth /sms-request /sms-auth'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'Already authenticated via 2nd factor'
    end

    visit '/sms-disable'
    page.find('#error_flash').text.must_equal 'SMS authentication has not been setup yet.'

    visit '/sms-setup'
    page.title.must_equal 'Setup SMS Backup Number'
    fill_in 'Password', :with=>'012345678'
    fill_in 'Phone Number', :with=>'(123) 456'
    click_button 'Setup SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Error setting up SMS authentication'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'Setup SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Error setting up SMS authentication'
    page.html.must_include 'invalid SMS phone number'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'
    page.find('#notice_flash').text.must_equal 'SMS authentication needs confirmation.'
    sms_phone.must_equal '1234567890'
    sms_message.must_match(/\ASMS confirmation code for www\.example\.com is \d{12}\z/)

    page.title.must_equal 'Confirm SMS Backup Number'
    fill_in 'SMS Code', :with=>"asdf"
    click_button 'Confirm SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Invalid or out of date SMS confirmation code used, must setup SMS authentication again.'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'

    visit '/sms-setup'
    page.find('#error_flash').text.must_equal 'SMS authentication needs confirmation.'
    page.title.must_equal 'Confirm SMS Backup Number'

    DB[:account_sms_codes].update(:code_issued_at=>Time.now - 310)
    sms_code = sms_message[/\d{12}\z/]
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Invalid or out of date SMS confirmation code used, must setup SMS authentication again.'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'
    sms_code = sms_message[/\d{12}\z/]
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'
    page.find('#notice_flash').text.must_equal 'SMS authentication has been setup.'

    %w'/sms-setup /sms-confirm'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'SMS authentication has already been setup.'
      page.current_path.must_equal '/'
    end

    logout
    login

    visit '/sms-auth'
    page.current_path.must_equal '/sms-request'
    page.find('#error_flash').text.must_equal 'No current SMS code for this account'

    sms_phone = sms_message = nil
    page.title.must_equal 'Send SMS Code'
    click_button 'Send SMS Code'
    sms_phone.must_equal '1234567890'
    sms_message.must_match(/\ASMS authentication code for www\.example\.com is \d{6}\z/)
    sms_code = sms_message[/\d{6}\z/]

    fill_in 'SMS Code', :with=>"asdf"
    click_button 'Authenticate via SMS Code'
    page.html.must_include 'invalid SMS code'
    page.find('#error_flash').text.must_equal 'Error authenticating via SMS code.'

    DB[:account_sms_codes].update(:code_issued_at=>Time.now - 310)
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Authenticate via SMS Code'
    page.find('#error_flash').text.must_equal 'No current SMS code for this account'

    click_button 'Send SMS Code'
    sms_code = sms_message[/\d{6}\z/]
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Authenticate via SMS Code'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'

    logout
    login

    visit '/sms-request'
    click_button 'Send SMS Code'

    5.times do
      click_button 'Authenticate via SMS Code'
      page.find('#error_flash').text.must_equal 'Error authenticating via SMS code.'
      page.current_path.must_equal '/sms-auth'
    end

    click_button 'Authenticate via SMS Code'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out.'
    page.current_path.must_equal '/two-factor-auth'

    visit '/sms-request'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out.'
    page.current_path.must_equal '/two-factor-auth'

    click_link 'Authenticate Using TOTP'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate via 2nd Factor'

    visit '/sms-disable'
    page.title.must_equal 'Disable Backup SMS Authentication'
    fill_in 'Password', :with=>'012345678'
    click_button 'Disable Backup SMS Authentication'
    page.find('#error_flash').text.must_equal 'Error disabling SMS authentication'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'Disable Backup SMS Authentication'
    page.find('#notice_flash').text.must_equal 'SMS authentication has been disabled.'
    page.current_path.must_equal '/'

    visit '/sms-setup'
    page.title.must_equal 'Setup SMS Backup Number'
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'
    sms_code = sms_message[/\d{12}\z/]
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'

    visit '/recovery-codes'
    page.title.must_equal 'View Authentication Recovery Codes'
    fill_in 'Password', :with=>'012345678'
    click_button 'View Authentication Recovery Codes'
    page.find('#error_flash').text.must_equal 'Unable to view recovery codes.'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'View Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    recovery_codes = find('#recovery-codes').text.split
    recovery_codes.length.must_equal 16
    recovery_code = recovery_codes.first

    logout
    login

    5.times do
      page.title.must_equal 'Enter Authentication Code'
      fill_in 'Authentication Code', :with=>"asdf"
      click_button 'Authenticate via 2nd Factor'
      page.find('#error_flash').text.must_equal 'Error logging in via two factor authentication'
      page.html.must_include 'Invalid authentication code'
    end

    page.title.must_equal 'Enter Authentication Code'
    fill_in 'Authentication Code', :with=>"asdf"
    click_button 'Authenticate via 2nd Factor'
    page.find('#error_flash').text.must_equal 'Authentication code use locked out due to numerous failures.'

    click_link "Authenticate Using SMS Code"
    click_button 'Send SMS Code'

    5.times do
      click_button 'Authenticate via SMS Code'
      page.find('#error_flash').text.must_equal 'Error authenticating via SMS code.'
    end

    click_button 'Authenticate via SMS Code'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out.'

    page.title.must_equal 'Enter Authentication Recovery Code'
    fill_in 'Recovery Code', :with=>"asdf"
    click_button 'Authenticate via Recovery Code'
    page.find('#error_flash').text.must_equal 'Error authenticating via recovery code.'
    page.html.must_include 'Invalid recovery code'

    fill_in 'Recovery Code', :with=>recovery_code
    click_button 'Authenticate via Recovery Code'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
    page.html.must_include 'With 2FA'

    visit '/recovery-codes'
    fill_in 'Password', :with=>'0123456789'
    click_button 'View Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    page.html.wont_include(recovery_code)
    find('#recovery-codes').text.split.length.must_equal 15

    click_button 'Add Authentication Recovery Codes'
    page.find('#error_flash').text.must_equal 'Unable to add recovery codes.'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'View Authentication Recovery Codes'
    find('#recovery-codes').text.split.length.must_equal 15
    fill_in 'Password', :with=>'0123456789'
    click_button 'Add Authentication Recovery Codes'
    page.find('#notice_flash').text.must_equal 'Additional authentication recovery codes have been added.'
    find('#recovery-codes').text.split.length.must_equal 16
    page.html.wont_include('Add Additional Authentication Recovery Codes')

    visit '/otp-disable'
    fill_in 'Password', :with=>'012345678'
    click_button 'Disable Two Factor Authentication'
    page.find('#error_flash').text.must_equal 'Error disabling up two factor authentication'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'Disable Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication has been disabled'
    page.html.must_include 'With 2FA'
    DB[:account_otp_keys].count.must_equal 0
  end

  it "should allow namespaced two factor authentication without password requirements" do
    rodauth do
      enable :login, :logout, :otp, :recovery_codes
      otp_drift 10
      two_factor_modifications_require_password? false
      otp_digits 8
      prefix "/auth"
    end
    roda do |r|
      r.on "auth" do
        r.rodauth
      end

      r.redirect '/auth/login' unless rodauth.logged_in?

      if rodauth.two_factor_authentication_setup?
        r.redirect '/auth/otp-auth' unless rodauth.two_factor_authenticated?
        view :content=>"With 2FA"
      else    
        view :content=>"Without 2FA"
      end
    end

    login
    page.html.must_include('Without 2FA')

    %w'/auth/otp-disable /auth/recovery-auth /auth/recovery-codes /auth/otp-auth'.each do
      visit '/auth/otp-disable'
      page.find('#error_flash').text.must_equal 'This account has not been setup for two factor authentication'
      page.current_path.must_equal '/auth/otp-setup'
    end

    page.title.must_equal 'Setup Two Factor Authentication'
    page.html.must_include '<svg' 
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret, :digits=>8)
    fill_in 'Authentication Code', :with=>"asdf"
    click_button 'Setup Two Factor Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up two factor authentication'
    page.html.must_include 'Invalid authentication code'

    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'With 2FA'
    reset_otp_last_use

    visit '/auth/logout'
    click_button 'Logout'
    login(:visit=>false)

    page.current_path.must_equal '/auth/otp-auth'

    %w'/auth/otp-disable /auth/recovery-codes /auth/otp-setup'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'You need to authenticate via 2nd factor before continuing.'
      page.current_path.must_equal '/auth/otp-auth'
    end

    page.title.must_equal 'Enter Authentication Code'
    fill_in 'Authentication Code', :with=>"asdf"
    click_button 'Authenticate via 2nd Factor'
    page.find('#error_flash').text.must_equal 'Error logging in via two factor authentication'
    page.html.must_include 'Invalid authentication code'

    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate via 2nd Factor'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
    page.html.must_include 'With 2FA'
    reset_otp_last_use

    visit '/auth/otp-auth'
    page.find('#error_flash').text.must_equal 'Already authenticated via 2nd factor'

    visit '/auth/otp-setup'
    page.find('#error_flash').text.must_equal 'You have already setup two factor authentication'

    visit '/auth/recovery-auth'
    page.find('#error_flash').text.must_equal 'Already authenticated via 2nd factor'

    visit '/auth/recovery-codes'
    page.title.must_equal 'View Authentication Recovery Codes'
    click_button 'View Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    find('#recovery-codes').text.split.length.must_equal 0

    click_button 'Add Authentication Recovery Codes'
    page.find('#notice_flash').text.must_equal 'Additional authentication recovery codes have been added.'
    recovery_codes = find('#recovery-codes').text.split
    recovery_codes.length.must_equal 16
    recovery_code = recovery_codes.first
    page.html.wont_include('Add Additional Authentication Recovery Codes')

    visit '/auth/logout'
    click_button 'Logout'
    login(:visit=>false)

    5.times do
      page.title.must_equal 'Enter Authentication Code'
      fill_in 'Authentication Code', :with=>"asdf"
      click_button 'Authenticate via 2nd Factor'
      page.find('#error_flash').text.must_equal 'Error logging in via two factor authentication'
      page.html.must_include 'Invalid authentication code'
    end

    page.title.must_equal 'Enter Authentication Code'
    fill_in 'Authentication Code', :with=>"asdf"
    click_button 'Authenticate via 2nd Factor'

    page.find('#error_flash').text.must_equal 'Authentication code use locked out due to numerous failures.'
    page.title.must_equal 'Enter Authentication Recovery Code'
    fill_in 'Recovery Code', :with=>"asdf"
    click_button 'Authenticate via Recovery Code'
    page.find('#error_flash').text.must_equal 'Error authenticating via recovery code.'
    page.html.must_include 'Invalid recovery code'
    fill_in 'Recovery Code', :with=>recovery_code
    click_button 'Authenticate via Recovery Code'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
    page.html.must_include 'With 2FA'

    visit '/auth/recovery-codes'
    click_button 'View Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    page.html.wont_include(recovery_code)
    find('#recovery-codes').text.split.length.must_equal 15
    click_button 'Add Authentication Recovery Codes'
    page.find('#notice_flash').text.must_equal 'Additional authentication recovery codes have been added.'
    find('#recovery-codes').text.split.length.must_equal 16
    page.html.wont_include('Add Additional Authentication Recovery Codes')

    visit '/auth/otp-disable'
    click_button 'Disable Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication has been disabled'
    page.html.must_include 'With 2FA'
    DB[:account_otp_keys].count.must_equal 0
  end

  it "should require login and OTP authentication to perform certain actions if user signed up for OTP" do
    rodauth do
      enable :login, :logout, :change_password, :change_login, :close_account, :otp
      otp_drift 10
    end
    roda do |r|
      r.rodauth

      r.is "a" do
        rodauth.require_authentication
        view(:content=>"aaa")
      end

      view(:content=>"bbb")
    end

    %w'/change-password /change-login /close-account /a'.each do |path|
      visit '/change-password'
      page.current_path.must_equal '/login'
    end

    login

    %w'/change-password /change-login /close-account /a'.each do |path|
      visit path
      page.current_path.must_equal path
    end

    visit '/otp-setup'
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'
    page.current_path.must_equal '/'

    logout
    login

    %w'/change-password /change-login /close-account /a'.each do |path|
      visit path
      page.current_path.must_equal '/otp-auth'
    end

    reset_otp_last_use
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate via 2nd Factor'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
    page.html.must_include 'bbb'

    visit '/otp-disable'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Disable Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication has been disabled'
    page.html.must_include 'bbb'
    visit 'a'
    page.html.must_include 'aaa'
  end

  it "should allow returning to requested location when two factor auth was required" do
    rodauth do
      enable :login, :logout, :otp
      two_factor_auth_return_to_requested_location? true
      two_factor_auth_redirect "/"
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
      r.get('page') do
        rodauth.require_authentication
        view :content=>"Passed Authentication Required: #{r.params['foo']}"
      end
    end

    login

    visit '/otp-setup'
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication is now setup'

    logout
    reset_otp_last_use
    login

    visit '/page?foo=bar'
    page.current_path.must_equal '/otp-auth'

    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate via 2nd Factor'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
    page.html.must_include "Passed Authentication Required: bar"
  end

  it "should handle attempts to insert a duplicate recovery code" do
    keys = ['a', 'a', 'b']
    interval = 1000000
    rodauth do
      enable :login, :logout, :otp, :recovery_codes
      otp_interval interval
      recovery_codes_limit 2
      new_recovery_code{keys.shift}
    end
    roda do |r|
      r.rodauth

      r.redirect '/login' unless rodauth.logged_in?

      if rodauth.two_factor_authentication_setup?
        r.redirect '/otp-auth' unless rodauth.authenticated?
        view :content=>"With OTP"
      else    
        view :content=>"Without OTP"
      end
    end

    login
    page.html.must_include('Without OTP')

    visit '/otp-auth'
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret, :interval=>interval)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication is now setup'
    page.current_path.must_equal '/'

    visit '/recovery-codes'
    fill_in 'Password', :with=>'0123456789'
    click_button 'View Authentication Recovery Codes'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Add Authentication Recovery Codes'

    DB[:account_recovery_codes].select_order_map(:code).must_equal ['a', 'b']
  end

  it "should handle two factor lockout when using rodauth.require_two_factor_setup and rodauth.require_authentication" do
    rodauth do
      enable :login, :logout, :otp
      otp_drift 10
    end
    roda do |r|
      r.rodauth
      rodauth.require_authentication
      rodauth.require_two_factor_setup

      view :content=>"Logged in"
    end

    login
    page.title.must_equal 'Setup Two Factor Authentication'
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged in'
    reset_otp_last_use

    logout
    login

    6.times do
      page.title.must_equal 'Enter Authentication Code'
      fill_in 'Authentication Code', :with=>'foo'
      click_button 'Authenticate via 2nd Factor'
    end
    page.find('#error_flash').text.must_equal 'Authentication code use locked out due to numerous failures.'
    page.title.must_equal 'Authenticate Using 2nd Factor'
  end

  it "should allow two factor authentication setup, login, removal without recovery" do
    rodauth do
      enable :login, :logout, :otp
      otp_drift 10
      otp_lockout_redirect '/'
    end
    roda do |r|
      r.rodauth

      r.redirect '/login' unless rodauth.logged_in?

      if rodauth.two_factor_authentication_setup?
        if rodauth.otp_locked_out?
          view :content=>"OTP Locked Out"
        else
          r.redirect '/otp-auth' unless rodauth.authenticated?
          view :content=>"With OTP"
        end
      else    
        view :content=>"Without OTP"
      end
    end

    visit '/recovery-auth'
    page.current_path.must_equal '/login'
    visit '/recovery-codes'
    page.current_path.must_equal '/login'

    login
    page.html.must_include('Without OTP')

    visit '/otp-setup'
    page.title.must_equal 'Setup Two Factor Authentication'
    page.html.must_include '<svg' 
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'With OTP'
    reset_otp_last_use

    logout
    login

    visit '/otp-auth'
    6.times do
      page.title.must_equal 'Enter Authentication Code'
      fill_in 'Authentication Code', :with=>'foo'
      click_button 'Authenticate via 2nd Factor'
    end
    page.find('#error_flash').text.must_equal 'Authentication code use locked out due to numerous failures.'
    page.body.must_include 'OTP Locked Out'
    page.current_path.must_equal '/'
    DB[:account_otp_keys].update(:num_failures=>0)

    visit '/otp-auth'
    page.title.must_equal 'Enter Authentication Code'
    page.html.wont_include 'Authenticate using recovery code'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate via 2nd Factor'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
    page.html.must_include 'With OTP'

    visit '/otp-disable'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Disable Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication has been disabled'
    page.html.must_include 'Without OTP'
    DB[:account_otp_keys].count.must_equal 0
  end

  it "should remove otp data when closing accounts" do
    rodauth do
      enable :login, :logout, :otp, :recovery_codes, :sms_codes, :close_account
      otp_drift 10
      two_factor_modifications_require_password? false
      close_account_requires_password? false
      sms_send{|*|}
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>"With OTP"}
    end

    login

    visit '/otp-setup'
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'

    visit '/sms-setup'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'

    visit '/recovery-codes'
    click_button 'View Authentication Recovery Codes'
    click_button 'Add Authentication Recovery Codes'

    DB[:account_otp_keys].count.must_equal 1
    DB[:account_recovery_codes].count.must_equal 16
    DB[:account_sms_codes].count.must_equal 1
    visit '/close-account'
    click_button 'Close Account'
    [:account_otp_keys, :account_recovery_codes, :account_sms_codes].each do |t|
      DB[t].count.must_equal 0
    end
  end

  it "should have recovery_codes and sms_codes work when used without otp" do
    sms_code, sms_phone, sms_message = nil
    rodauth do
      enable :login, :logout, :recovery_codes, :sms_codes
      sms_send do |phone, msg|
        sms_phone = phone
        sms_message = msg
        sms_code = msg[/\d+\z/]
      end
    end
    roda do |r|
      r.rodauth

      r.redirect '/login' unless rodauth.logged_in?

      if rodauth.two_factor_authentication_setup?
        r.redirect '/sms-request' unless rodauth.authenticated?
        view :content=>"With OTP"
      else    
        view :content=>"Without OTP"
      end
    end

    login
    page.html.must_include('Without OTP')

    %w'/recovery-auth /recovery-codes'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'This account has not been setup for two factor authentication'
      page.current_path.must_equal '/sms-setup'
    end

    %w'/sms-disable /sms-request /sms-auth'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'SMS authentication has not been setup yet.'
      page.current_path.must_equal '/sms-setup'
    end

    visit '/sms-setup'
    page.title.must_equal 'Setup SMS Backup Number'
    fill_in 'Password', :with=>'012345678'
    fill_in 'Phone Number', :with=>'(123) 456'
    click_button 'Setup SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Error setting up SMS authentication'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'Setup SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Error setting up SMS authentication'
    page.html.must_include 'invalid SMS phone number'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'
    page.find('#notice_flash').text.must_equal 'SMS authentication needs confirmation.'
    sms_phone.must_equal '1234567890'
    sms_message.must_match(/\ASMS confirmation code for www\.example\.com is \d{12}\z/)

    page.title.must_equal 'Confirm SMS Backup Number'
    fill_in 'SMS Code', :with=>"asdf"
    click_button 'Confirm SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Invalid or out of date SMS confirmation code used, must setup SMS authentication again.'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'

    visit '/sms-setup'
    page.find('#error_flash').text.must_equal 'SMS authentication needs confirmation.'
    page.title.must_equal 'Confirm SMS Backup Number'

    DB[:account_sms_codes].update(:code_issued_at=>Time.now - 310)
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Invalid or out of date SMS confirmation code used, must setup SMS authentication again.'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'
    page.find('#notice_flash').text.must_equal "SMS authentication has been setup."

    visit '/recovery-codes'
    page.title.must_equal 'View Authentication Recovery Codes'
    fill_in 'Password', :with=>'012345678'
    click_button 'View Authentication Recovery Codes'
    page.find('#error_flash').text.must_equal 'Unable to view recovery codes.'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'View Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    recovery_codes = find('#recovery-codes').text.split
    recovery_codes.length.must_equal 0
    recovery_code = recovery_codes.first

    fill_in 'Password', :with=>'0123456789'
    click_button 'Add Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    recovery_codes = find('#recovery-codes').text.split
    recovery_codes.length.must_equal 16
    recovery_code = recovery_codes.first

    logout
    login
    page.current_path.must_equal '/sms-request'

    %w'/recovery-codes /sms-setup /sms-disable /sms-confirm'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'You need to authenticate via 2nd factor before continuing.'
      page.current_path.must_equal '/two-factor-auth'
    end

    visit '/sms-auth'
    page.current_path.must_equal '/sms-request'
    page.find('#error_flash').text.must_equal 'No current SMS code for this account'

    sms_phone = sms_message = nil
    page.title.must_equal 'Send SMS Code'
    click_button 'Send SMS Code'
    sms_phone.must_equal '1234567890'
    sms_message.must_match(/\ASMS authentication code for www\.example\.com is \d{6}\z/)

    fill_in 'SMS Code', :with=>"asdf"
    click_button 'Authenticate via SMS Code'
    page.html.must_include 'invalid SMS code'
    page.find('#error_flash').text.must_equal 'Error authenticating via SMS code.'

    DB[:account_sms_codes].update(:code_issued_at=>Time.now - 310)
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Authenticate via SMS Code'
    page.find('#error_flash').text.must_equal 'No current SMS code for this account'

    click_button 'Send SMS Code'
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Authenticate via SMS Code'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'

    %w'/recovery-auth /sms-request /sms-auth'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'Already authenticated via 2nd factor'
    end

    %w'/sms-setup /sms-confirm'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'SMS authentication has already been setup.'
      page.current_path.must_equal '/'
    end

    logout
    login

    click_button 'Send SMS Code'

    5.times do
      click_button 'Authenticate via SMS Code'
      page.find('#error_flash').text.must_equal 'Error authenticating via SMS code.'
      page.current_path.must_equal '/sms-auth'
    end

    click_button 'Authenticate via SMS Code'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out.'
    page.current_path.must_equal '/recovery-auth'

    visit '/sms-request'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out.'
    page.current_path.must_equal '/recovery-auth'

    page.title.must_equal 'Enter Authentication Recovery Code'
    fill_in 'Recovery Code', :with=>"asdf"
    click_button 'Authenticate via Recovery Code'
    page.find('#error_flash').text.must_equal 'Error authenticating via recovery code.'
    page.html.must_include 'Invalid recovery code'

    fill_in 'Recovery Code', :with=>recovery_code
    click_button 'Authenticate via Recovery Code'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
    page.html.must_include 'With OTP'

    visit '/recovery-codes'
    fill_in 'Password', :with=>'0123456789'
    click_button 'View Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    page.html.wont_include(recovery_code)
    find('#recovery-codes').text.split.length.must_equal 15

    click_button 'Add Authentication Recovery Codes'
    page.find('#error_flash').text.must_equal 'Unable to add recovery codes.'
    page.html.must_include 'invalid password'

    visit '/sms-disable'
    page.title.must_equal 'Disable Backup SMS Authentication'
    fill_in 'Password', :with=>'012345678'
    click_button 'Disable Backup SMS Authentication'
    page.find('#error_flash').text.must_equal 'Error disabling SMS authentication'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'Disable Backup SMS Authentication'
    page.find('#notice_flash').text.must_equal 'SMS authentication has been disabled.'
    page.current_path.must_equal '/'

    DB[:account_sms_codes].count.must_equal 0
  end

  it "should have recovery_codes work when used by itself" do
    rodauth do
      enable :login, :logout, :recovery_codes
    end
    roda do |r|
      r.rodauth

      r.redirect '/login' unless rodauth.logged_in?

      if rodauth.two_factor_authentication_setup?
        r.redirect '/recovery-auth' unless rodauth.authenticated?
        view :content=>"With OTP"
      else    
        view :content=>"Without OTP"
      end
    end

    login
    page.html.must_include('Without OTP')

    visit '/recovery-auth'
    page.find('#error_flash').text.must_equal 'This account has not been setup for two factor authentication'
    page.current_path.must_equal '/recovery-codes'

    page.title.must_equal 'View Authentication Recovery Codes'
    fill_in 'Password', :with=>'012345678'
    click_button 'View Authentication Recovery Codes'
    page.find('#error_flash').text.must_equal 'Unable to view recovery codes.'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'View Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    recovery_codes = find('#recovery-codes').text.split
    recovery_codes.length.must_equal 0
    fill_in 'Password', :with=>'0123456789'
    click_button 'Add Authentication Recovery Codes'
    recovery_codes = find('#recovery-codes').text.split
    recovery_codes.length.must_equal 16
    recovery_code = recovery_codes.first

    logout
    login
    page.current_path.must_equal '/recovery-auth'

    visit '/recovery-codes'
    page.find('#error_flash').text.must_equal 'You need to authenticate via 2nd factor before continuing.'
    page.current_path.must_equal '/recovery-auth'

    page.title.must_equal 'Enter Authentication Recovery Code'
    fill_in 'Recovery Code', :with=>"asdf"
    click_button 'Authenticate via Recovery Code'
    page.find('#error_flash').text.must_equal 'Error authenticating via recovery code.'
    page.html.must_include 'Invalid recovery code'

    fill_in 'Recovery Code', :with=>recovery_code
    click_button 'Authenticate via Recovery Code'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
    page.html.must_include 'With OTP'

    visit '/recovery-codes'
    fill_in 'Password', :with=>'0123456789'
    click_button 'View Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    page.html.wont_include(recovery_code)
    page.html.wont_include('Add Authentication Recovery Codes')
    find('#recovery-codes').text.split.length.must_equal 16
  end

  it "should have sms_codes work when used by itself" do
    sms_code, sms_phone, sms_message = nil
    rodauth do
      enable :login, :logout, :sms_codes
      sms_send do |phone, msg|
        sms_phone = phone
        sms_message = msg
        sms_code = msg[/\d+\z/]
      end
    end
    roda do |r|
      r.rodauth

      r.redirect '/login' unless rodauth.logged_in?

      if rodauth.two_factor_authentication_setup?
        if rodauth.sms_locked_out?
          view :content=>"With SMS Locked Out"
        else
          rodauth.require_two_factor_authenticated
          view :content=>"With OTP"
        end
      else    
        view :content=>"Without OTP"
      end
    end

    login
    page.html.must_include('Without OTP')

    %w'/sms-disable /sms-request /sms-auth'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'SMS authentication has not been setup yet.'
      page.current_path.must_equal '/sms-setup'
    end

    visit '/sms-setup'
    page.title.must_equal 'Setup SMS Backup Number'
    fill_in 'Password', :with=>'012345678'
    fill_in 'Phone Number', :with=>'(123) 456'
    click_button 'Setup SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Error setting up SMS authentication'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'Setup SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Error setting up SMS authentication'
    page.html.must_include 'invalid SMS phone number'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'
    page.find('#notice_flash').text.must_equal 'SMS authentication needs confirmation.'
    sms_phone.must_equal '1234567890'
    sms_message.must_match(/\ASMS confirmation code for www\.example\.com is \d{12}\z/)

    page.title.must_equal 'Confirm SMS Backup Number'
    fill_in 'SMS Code', :with=>"asdf"
    click_button 'Confirm SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Invalid or out of date SMS confirmation code used, must setup SMS authentication again.'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'

    visit '/sms-setup'
    page.find('#error_flash').text.must_equal 'SMS authentication needs confirmation.'
    page.title.must_equal 'Confirm SMS Backup Number'

    DB[:account_sms_codes].update(:code_issued_at=>Time.now - 310)
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Invalid or out of date SMS confirmation code used, must setup SMS authentication again.'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'
    page.find('#notice_flash').text.must_equal "SMS authentication has been setup."

    logout
    login
    page.current_path.must_equal '/sms-request'

    %w'/sms-setup /sms-disable /sms-confirm'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'You need to authenticate via 2nd factor before continuing.'
      page.current_path.must_equal '/sms-request'
    end

    visit '/sms-auth'
    page.current_path.must_equal '/sms-request'
    page.find('#error_flash').text.must_equal 'No current SMS code for this account'

    sms_phone = sms_message = nil
    page.title.must_equal 'Send SMS Code'
    click_button 'Send SMS Code'
    sms_phone.must_equal '1234567890'
    sms_message.must_match(/\ASMS authentication code for www\.example\.com is \d{6}\z/)

    fill_in 'SMS Code', :with=>"asdf"
    click_button 'Authenticate via SMS Code'
    page.html.must_include 'invalid SMS code'
    page.find('#error_flash').text.must_equal 'Error authenticating via SMS code.'

    DB[:account_sms_codes].update(:code_issued_at=>Time.now - 310)
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Authenticate via SMS Code'
    page.find('#error_flash').text.must_equal 'No current SMS code for this account'

    click_button 'Send SMS Code'
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Authenticate via SMS Code'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'

    %w'/sms-request /sms-auth'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'Already authenticated via 2nd factor'
    end

    %w'/sms-setup /sms-confirm'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'SMS authentication has already been setup.'
      page.current_path.must_equal '/'
    end

    logout
    login

    click_button 'Send SMS Code'

    5.times do
      click_button 'Authenticate via SMS Code'
      page.find('#error_flash').text.must_equal 'Error authenticating via SMS code.'
      page.current_path.must_equal '/sms-auth'
    end

    click_button 'Authenticate via SMS Code'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out.'
    page.current_path.must_equal '/two-factor-auth'

    visit '/'
    page.body.must_include "With SMS Locked Out"

    visit '/sms-request'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out.'
    page.current_path.must_equal '/two-factor-auth'

    DB[:account_sms_codes].update(:num_failures=>0)
    visit '/sms-request'
    click_button 'Send SMS Code'
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Authenticate via SMS Code'

    visit '/sms-disable'
    page.title.must_equal 'Disable Backup SMS Authentication'
    fill_in 'Password', :with=>'012345678'
    click_button 'Disable Backup SMS Authentication'
    page.find('#error_flash').text.must_equal 'Error disabling SMS authentication'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'Disable Backup SMS Authentication'
    page.find('#notice_flash').text.must_equal 'SMS authentication has been disabled.'
    page.current_path.must_equal '/'

    DB[:account_sms_codes].count.must_equal 0
  end

  it "should allow two factor authentication via jwt" do
    hmac_secret = sms_phone = sms_message = sms_code = nil
    rodauth do
      enable :login, :logout, :otp, :recovery_codes, :sms_codes
      otp_drift 10
      hmac_secret do
        hmac_secret
      end
      sms_send do |phone, msg|
        sms_phone = phone
        sms_message = msg
        sms_code = msg[/\d+\z/]
      end
    end
    roda(:jwt) do |r|
      r.rodauth

      if rodauth.logged_in?
        if rodauth.two_factor_authentication_setup?
          if rodauth.authenticated?
           [1]
          else
           [2]
          end
        else    
         [3]
        end
      else
        [4]
      end
    end

    json_request.must_equal [200, [4]]
    json_login
    json_request.must_equal [200, [3]]

    %w'/otp-disable /recovery-auth /recovery-codes /sms-setup /sms-confirm /otp-auth'.each do |path|
      json_request(path).must_equal [403, {'error'=>'This account has not been setup for two factor authentication'}]
    end
    %w'/sms-disable /sms-request /sms-auth'.each do |path|
      json_request(path).must_equal [403, {'error'=>'SMS authentication has not been setup yet.'}]
    end

    secret = (ROTP::Base32.respond_to?(:random_base32) ? ROTP::Base32.random_base32 : ROTP::Base32.random).downcase
    totp = ROTP::TOTP.new(secret)

    res = json_request('/otp-setup', :password=>'123456', :otp_secret=>secret)
    res.must_equal [401, {'error'=>'Error setting up two factor authentication', "field-error"=>["password", 'invalid password']}] 

    res = json_request('/otp-setup', :password=>'0123456789', :otp=>'adsf', :otp_secret=>secret)
    res.must_equal [401, {'error'=>'Error setting up two factor authentication', "field-error"=>["otp", 'Invalid authentication code']}] 

    res = json_request('/otp-setup', :password=>'0123456789', :otp=>'adsf', :otp_secret=>'asdf')
    res.must_equal [422, {'error'=>'Error setting up two factor authentication', "field-error"=>["otp_secret", 'invalid secret']}] 

    res = json_request('/otp-setup', :password=>'0123456789', :otp=>totp.now, :otp_secret=>secret)
    res.must_equal [200, {'success'=>'Two factor authentication is now setup'}]
    reset_otp_last_use

    json_logout
    json_login
    json_request.must_equal [200, [2]]

    %w'/otp-disable /recovery-codes /otp-setup /sms-setup /sms-disable /sms-confirm'.each do |path|
      json_request(path).must_equal [401, {'error'=>'You need to authenticate via 2nd factor before continuing.'}]
    end

    res = json_request('/otp-auth', :otp=>'adsf')
    res.must_equal [401, {'error'=>'Error logging in via two factor authentication', "field-error"=>["otp", 'Invalid authentication code']}] 

    res = json_request('/otp-auth', :otp=>totp.now)
    res.must_equal [200, {'success'=>'You have been authenticated via 2nd factor'}]
    json_request.must_equal [200, [1]]
    reset_otp_last_use

    res = json_request('/otp-setup')
    res.must_equal [400, {'error'=>'You have already setup two factor authentication'}] 

    %w'/otp-auth /recovery-auth /sms-request /sms-auth'.each do |path|
      res = json_request(path)
      res.must_equal [403, {'error'=>'Already authenticated via 2nd factor'}] 
    end

    res = json_request('/sms-disable')
    res.must_equal [403, {'error'=>'SMS authentication has not been setup yet.'}] 

    res = json_request('/sms-setup', :password=>'012345678', "sms-phone"=>'(123) 456')
    res.must_equal [401, {'error'=>'Error setting up SMS authentication', "field-error"=>["password", 'invalid password']}] 

    res = json_request('/sms-setup', :password=>'0123456789', "sms-phone"=>'(123) 456')
    res.must_equal [422, {'error'=>'Error setting up SMS authentication', "field-error"=>["sms-phone", 'invalid SMS phone number']}] 

    res = json_request('/sms-setup', :password=>'0123456789', "sms-phone"=>'(123) 4567 890')
    res.must_equal [200, {'success'=>'SMS authentication needs confirmation.'}]

    sms_phone.must_equal '1234567890'
    sms_message.must_match(/\ASMS confirmation code for example\.com:? is \d{12}\z/)

    res = json_request('/sms-confirm', :sms_code=>'asdf')
    res.must_equal [401, {'error'=>'Invalid or out of date SMS confirmation code used, must setup SMS authentication again.'}] 

    res = json_request('/sms-setup', :password=>'0123456789', "sms-phone"=>'(123) 4567 890')
    res.must_equal [200, {'success'=>'SMS authentication needs confirmation.'}]

    DB[:account_sms_codes].update(:code_issued_at=>Time.now - 310)
    res = json_request('/sms-confirm', :sms_code=>sms_code)
    res.must_equal [401, {'error'=>'Invalid or out of date SMS confirmation code used, must setup SMS authentication again.'}] 

    res = json_request('/sms-setup', :password=>'0123456789', "sms-phone"=>'(123) 4567 890')
    res.must_equal [200, {'success'=>'SMS authentication needs confirmation.'}]

    res = json_request('/sms-confirm', "sms-code"=>sms_code)
    res.must_equal [200, {'success'=>'SMS authentication has been setup.'}]

    %w'/sms-setup /sms-confirm'.each do |path|
      res = json_request(path)
      res.must_equal [403, {'error'=>'SMS authentication has already been setup.'}] 
    end

    json_logout
    json_login

    res = json_request('/sms-auth')
    res.must_equal [401, {'error'=>'No current SMS code for this account'}]

    sms_phone = sms_message = nil
    res = json_request('/sms-request')
    res.must_equal [200, {'success'=>'SMS authentication code has been sent.'}]
    sms_phone.must_equal '1234567890'
    sms_message.must_match(/\ASMS authentication code for example\.com:? is \d{6}\z/)

    res = json_request('/sms-auth')
    res.must_equal [401, {'error'=>'Error authenticating via SMS code.', "field-error"=>["sms-code", "invalid SMS code"]}]

    DB[:account_sms_codes].update(:code_issued_at=>Time.now - 310)
    res = json_request('/sms-auth')
    res.must_equal [401, {'error'=>'No current SMS code for this account'}]

    res = json_request('/sms-request')
    res.must_equal [200, {'success'=>'SMS authentication code has been sent.'}]

    res = json_request('/sms-auth', 'sms-code'=>sms_code)
    res.must_equal [200, {'success'=>'You have been authenticated via 2nd factor'}]
    json_request.must_equal [200, [1]]

    json_logout
    json_login

    res = json_request('/sms-request')
    res.must_equal [200, {'success'=>'SMS authentication code has been sent.'}]

    5.times do
      res = json_request('/sms-auth')
      res.must_equal [401, {'error'=>'Error authenticating via SMS code.', "field-error"=>["sms-code", "invalid SMS code"]}]
    end

    res = json_request('/sms-auth')
    res.must_equal [403, {'error'=>'SMS authentication has been locked out.'}]

    res = json_request('/sms-request')
    res.must_equal [403, {'error'=>'SMS authentication has been locked out.'}]

    res = json_request('/otp-auth', :otp=>totp.now)
    res.must_equal [200, {'success'=>'You have been authenticated via 2nd factor'}]
    json_request.must_equal [200, [1]]

    res = json_request('/sms-disable', :password=>'012345678')
    res.must_equal [401, {'error'=>'Error disabling SMS authentication', "field-error"=>["password", 'invalid password']}]

    res = json_request('/sms-disable', :password=>'0123456789')
    res.must_equal [200, {'success'=>'SMS authentication has been disabled.'}]

    res = json_request('/sms-setup', :password=>'0123456789', "sms-phone"=>'(123) 4567 890')
    res.must_equal [200, {'success'=>'SMS authentication needs confirmation.'}]

    res = json_request('/sms-confirm', "sms-code"=>sms_code)
    res.must_equal [200, {'success'=>'SMS authentication has been setup.'}]

    res = json_request('/recovery-codes', :password=>'asdf')
    res.must_equal [401, {'error'=>'Unable to view recovery codes.', "field-error"=>["password", 'invalid password']}] 

    res = json_request('/recovery-codes', :password=>'0123456789')
    res[1].delete('codes').must_be_empty
    res.must_equal [200, {'success'=>''}]

    res = json_request('/recovery-codes', :password=>'0123456789', :add=>'1')
    codes = res[1].delete('codes')
    codes.sort.must_equal DB[:account_recovery_codes].select_map(:code).sort
    codes.length.must_equal 16
    res.must_equal [200, {'success'=>'Additional authentication recovery codes have been added.'}]

    json_logout
    json_login

    5.times do
      res = json_request('/otp-auth', :otp=>'asdf')
      res.must_equal [401, {'error'=>'Error logging in via two factor authentication', "field-error"=>["otp", 'Invalid authentication code']}] 
    end

    res = json_request('/otp-auth', :otp=>'asdf')
    res.must_equal [403, {'error'=>'Authentication code use locked out due to numerous failures.'}] 

    res = json_request('/sms-request')
    5.times do
      res = json_request('/sms-auth')
      res.must_equal [401, {'error'=>'Error authenticating via SMS code.', "field-error"=>["sms-code", "invalid SMS code"]}]
    end

    res = json_request('/otp-auth', :otp=>'asdf')
    res.must_equal [403, {'error'=>'Authentication code use locked out due to numerous failures.'}] 

    res = json_request('/sms-auth')
    res.must_equal [403, {'error'=>'SMS authentication has been locked out.'}] 

    res = json_request('/recovery-auth', 'recovery-code'=>'adsf')
    res.must_equal [401, {'error'=>'Error authenticating via recovery code.', "field-error"=>["recovery-code", "Invalid recovery code"]}]

    res = json_request('/recovery-auth', 'recovery-code'=>codes.first)
    res.must_equal [200, {'success'=>'You have been authenticated via 2nd factor'}]
    json_request.must_equal [200, [1]]

    res = json_request('/recovery-codes', :password=>'0123456789')
    codes2 = res[1].delete('codes')
    codes2.sort.must_equal codes[1..-1].sort
    res.must_equal [200, {'success'=>''}]

    res = json_request('/recovery-codes', :password=>'012345678', :add=>'1')
    res.must_equal [401, {'error'=>'Unable to add recovery codes.', "field-error"=>["password", 'invalid password']}] 

    res = json_request('/recovery-codes', :password=>'0123456789', :add=>'1')
    codes3 = res[1].delete('codes')
    (codes3 - codes2).length.must_equal 1
    res.must_equal [200, {'success'=>'Additional authentication recovery codes have been added.'}]

    res = json_request('/otp-disable', :password=>'012345678')
    res.must_equal [401, {'error'=>'Error disabling up two factor authentication', "field-error"=>["password", 'invalid password']}] 

    res = json_request('/otp-disable', :password=>'0123456789')
    res.must_equal [200, {'success'=>'Two factor authentication has been disabled'}]

    DB[:account_otp_keys].count.must_equal 0

    hmac_secret  = "123"
    res = json_request('/otp-setup')
    secret = res[1].delete("otp_secret")
    raw_secret = res[1].delete("otp_raw_secret")
    res.must_equal [422, {'error'=>'Error setting up two factor authentication', "field-error"=>["otp_secret", 'invalid secret']}] 

    totp = ROTP::TOTP.new(secret)
    hmac_secret  = "321"
    res = json_request('/otp-setup', :password=>'0123456789', :otp=>totp.now, :otp_secret=>secret, :otp_raw_secret=>raw_secret)
    res.must_equal [422, {'error'=>'Error setting up two factor authentication', "field-error"=>["otp_secret", 'invalid secret']}] 

    reset_otp_last_use
    hmac_secret  = "123"
    res = json_request('/otp-setup', :password=>'0123456789', :otp=>totp.now, :otp_secret=>secret, :otp_raw_secret=>raw_secret)
    res.must_equal [200, {'success'=>'Two factor authentication is now setup'}]
    reset_otp_last_use

    json_logout
    json_login

    hmac_secret  = "321"
    res = json_request('/otp-auth', :otp=>totp.now)
    res.must_equal [401, {'error'=>'Error logging in via two factor authentication', "field-error"=>["otp", 'Invalid authentication code']}] 

    hmac_secret  = "123"
    res = json_request('/otp-auth', :otp=>totp.now)
    res.must_equal [200, {'success'=>'You have been authenticated via 2nd factor'}]
    json_request.must_equal [200, [1]]
  end

  it "should call the two factor auth before hook only when setup" do
    before_called = false
    rodauth do
      enable :login, :otp, :logout
      before_otp_auth_route{before_called = true}
      otp_drift 10
    end
    roda do |r|
      r.rodauth

      r.redirect '/login' unless rodauth.logged_in?

      if rodauth.two_factor_authentication_setup?
        r.redirect '/otp-auth' unless rodauth.authenticated?
        view :content=>"With OTP"
      else    
        view :content=>"Without OTP"
      end
    end

    login
    page.html.must_include('Without OTP')

    visit '/otp-auth'
    before_called.must_equal false
    page.current_path.must_equal '/otp-setup'

    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'With OTP'

    logout
    before_called.must_equal false
    login
    page.current_path.must_equal '/otp-auth'
    before_called.must_equal true
  end

  it "should show as user is authenticated when setting up OTP" do
    no_freeze!
    rodauth do
      enable :login, :otp
      otp_drift 10
      hmac_secret '123'
    end
    roda do |r|
      r.rodauth
      r.redirect '/login' unless rodauth.logged_in?
      r.redirect '/otp-setup' unless  rodauth.two_factor_authentication_setup?
      view :content=>"With OTP"
    end
    @app.plugin :render, :layout_opts=>{:path=>'spec/views/layout-auth-check.str'}

    login

    page.title.must_equal 'Setup Two Factor Authentication'
    page.html.must_include 'Is Logged In'
    page.html.must_include 'Is Authenticated'
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'With OTP'
  end

  begin
    require 'webauthn/fake_client'
  rescue LoadError
  else
    it "should handle webauthn, otp, sms, and recovery codes in use together" do
      recovery_codes_primary = sms_codes_primary = false
      sms_phone = sms_message = nil
      require_password = false
      rodauth do
        enable :login, :logout, :webauthn, :otp, :sms_codes, :recovery_codes
        hmac_secret '123'
        sms_send do |phone, msg|
          sms_phone = phone
          sms_message = msg
        end
        two_factor_modifications_require_password?{require_password}
        sms_codes_primary?{sms_codes_primary}
        recovery_codes_primary?{recovery_codes_primary}
      end
      first_request = nil
      roda do |r|
        first_request ||= r
        r.rodauth

        rodauth.require_login

        r.on('2') do
          rodauth.require_authentication
          rodauth.require_two_factor_setup
          view :content=>"With Required 2nd Factor: #{rodauth.authenticated_by.last}"
        end

        if rodauth.two_factor_authentication_setup?
          rodauth.require_authentication
          view :content=>"With 2nd Factor: #{rodauth.authenticated_by.last}"
        else    
          view :content=>"Without 2nd Factor"
        end
      end

      login
      page.html.must_include 'Without 2nd Factor'
      origin = first_request.base_url
      webauthn_client1 = WebAuthn::FakeClient.new(origin)
      webauthn_client2 = WebAuthn::FakeClient.new(origin)

      %w'/two-factor-auth /two-factor-disable'.each do |path|
        visit path
        page.find('#error_flash').text.must_equal 'This account has not been setup for two factor authentication'
        page.current_path.must_equal '/two-factor-manage'
      end

      visit '/2'
      page.title.must_equal 'Manage Two Factor Authentication'
      page.html.must_match(/Setup Two Factor Authentication.*Setup WebAuthn Authentication.*Setup TOTP Authentication/m)
      page.html.wont_include 'Remove Two Factor Authentication'
      page.html.wont_include 'Setup Backup SMS Authentication'
      page.html.wont_include 'View Authentication Recovery Codes'

      sms_codes_primary = true
      visit page.current_path
      page.html.must_match(/Setup WebAuthn Authentication.*Setup TOTP Authentication.*Setup Backup SMS Authentication/m)
      page.html.wont_include 'View Authentication Recovery Codes'

      sms_codes_primary = false
      recovery_codes_primary = true
      visit page.current_path
      page.html.must_match(/Setup WebAuthn Authentication.*Setup TOTP Authentication.*View Authentication Recovery Codes/m)
      page.html.wont_include 'Setup Backup SMS Authentication'

      sms_codes_primary = true
      visit page.current_path
      page.html.must_match(/Setup WebAuthn Authentication.*Setup TOTP Authentication.*Setup Backup SMS Authentication.*View Authentication Recovery Codes/m)

      recovery_codes_primary = sms_codes_primary = false
      click_link 'Setup WebAuthn Authentication'
      challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
      fill_in 'webauthn_setup', :with=>webauthn_client1.create(challenge: challenge).to_json
      click_button 'Setup WebAuthn Authentication'
      page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
      page.current_path.must_equal '/'
      page.html.must_include 'With 2nd Factor: webauthn'

      visit '/2'
      page.html.must_include 'With Required 2nd Factor: webauthn'

      logout
      login

      page.title.must_equal 'Authenticate Using WebAuthn'
      challenge = JSON.parse(page.find('#rodauth-webauthn-auth-form')['data-credential-options'])['challenge']
      fill_in 'webauthn_auth', :with=>webauthn_client1.get(challenge: challenge).to_json
      click_button 'Authenticate Using WebAuthn'
      page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
      page.current_path.must_equal '/'
      page.html.must_include 'With 2nd Factor: webauthn'

      visit '/two-factor-manage'
      page.html.must_match(/Setup Two Factor Authentication.*Setup WebAuthn Authentication.*Setup TOTP Authentication.*Setup Backup SMS Authentication.*View Authentication Recovery Codes.*Remove Two Factor Authentication.*Remove WebAuthn Authenticator/m)

      click_link 'Setup TOTP Authentication'
      secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
      totp = ROTP::TOTP.new(secret)
      fill_in 'Authentication Code', :with=>totp.now
      click_button 'Setup Two Factor Authentication'
      page.find('#notice_flash').text.must_equal 'Two factor authentication is now setup'
      page.current_path.must_equal '/'
      page.html.must_include 'With 2nd Factor: webauthn'
      reset_otp_last_use
      
      logout
      login

      page.title.must_equal 'Authenticate Using 2nd Factor'
      page.html.must_match(/Authenticate Using WebAuthn.*Authenticate Using TOTP/m)
      page.html.wont_include 'Authenticate Using SMS Code'

      click_link 'Authenticate Using TOTP'
      fill_in 'Authentication Code', :with=>totp.now
      click_button 'Authenticate via 2nd Factor'
      page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
      page.html.must_include 'With 2nd Factor: totp'
      reset_otp_last_use

      visit '/two-factor-manage'
      page.html.must_match(/Setup Two Factor Authentication.*Setup WebAuthn Authentication.*Setup Backup SMS Authentication.*View Authentication Recovery Codes.*Remove Two Factor Authentication.*Remove WebAuthn Authenticator.*Disable TOTP Authentication/m)
      page.html.wont_include 'Setup TOTP Authentication'

      click_link 'View Authentication Recovery Codes'
      click_button 'View Authentication Recovery Codes'
      click_button 'Add Authentication Recovery Codes'
      page.find('#notice_flash').text.must_equal "Additional authentication recovery codes have been added."
      page.current_path.must_equal '/recovery-codes'

      visit '/two-factor-manage'
      click_link 'Setup WebAuthn Authentication'
      challenge = JSON.parse(page.find('#rodauth-webauthn-setup-form')['data-credential-options'])['challenge']
      fill_in 'webauthn_setup', :with=>webauthn_client2.create(challenge: challenge).to_json
      click_button 'Setup WebAuthn Authentication'
      page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
      page.current_path.must_equal '/'
      page.html.must_include 'With 2nd Factor: totp'

      visit '/two-factor-manage'
      click_link 'Setup Backup SMS Authentication'
      fill_in 'Phone Number', :with=>'(123) 456-7890'
      click_button 'Setup SMS Backup Number'
      page.find('#notice_flash').text.must_equal 'SMS authentication needs confirmation.'
      sms_phone.must_equal '1234567890'
      sms_message.must_match(/\ASMS confirmation code for www\.example\.com is \d{12}\z/)
      sms_code = sms_message[/\d{12}\z/]
      fill_in 'SMS Code', :with=>sms_code
      click_button 'Confirm SMS Backup Number'
      page.find('#notice_flash').text.must_equal 'SMS authentication has been setup.'
      page.html.must_include 'With 2nd Factor: totp'

      logout
      login

      page.html.must_match(/Authenticate Using WebAuthn.*Authenticate Using TOTP.*Authenticate Using SMS Code.*Authenticate Using Recovery Code/m)
      click_link 'Authenticate Using SMS Code'

      click_button 'Send SMS Code'
      sms_code = sms_message[/\d{6}\z/]
      fill_in 'SMS Code', :with=>sms_code
      click_button 'Authenticate via SMS Code'
      page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
      page.html.must_include 'With 2nd Factor: sms_code'

      visit '/two-factor-manage'
      page.html.must_match(/Setup Two Factor Authentication.*Setup WebAuthn Authentication.*View Authentication Recovery Codes.*Remove Two Factor Authentication.*Remove WebAuthn Authenticator.*Disable TOTP Authentication.*Disable SMS Authentication/m)
      page.html.wont_include 'Setup TOTP Authentication'
      page.html.wont_include 'Setup Backup SMS Authentication'

      click_link 'View Authentication Recovery Codes'
      page.title.must_equal 'View Authentication Recovery Codes'
      click_button 'View Authentication Recovery Codes'
      recovery_codes = find('#recovery-codes').text.split
      recovery_codes.length.must_equal 16
      recovery_code = recovery_codes.first

      logout
      login

      page.html.must_match(/Authenticate Using WebAuthn.*Authenticate Using TOTP.*Authenticate Using SMS Code.*Authenticate Using Recovery Code/m)
      click_link 'Authenticate Using Recovery Code'
      fill_in 'Recovery Code', :with=>recovery_code
      click_button 'Authenticate via Recovery Code'
      page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
      page.html.must_include 'With 2nd Factor: recovery_code'

      require_password = true

      visit '/two-factor-manage'
      click_link 'Remove All 2nd Factor Authentication Methods'
      page.title.must_equal 'Remove All 2nd Factor Authentication Methods'
      click_button 'Remove All 2nd Factor Authentication Methods'
      page.find('#error_flash').text.must_equal 'Unable to remove all 2nd factor authentication methods'
      page.html.must_include 'invalid password'

      fill_in 'Password', :with=>'0123456789'
      click_button 'Remove All 2nd Factor Authentication Methods'
      page.find('#notice_flash').text.must_equal 'All 2nd factor authentication methods have been disabled'
      page.html.must_include 'Without 2nd Factor'
      [:account_webauthn_user_ids, :account_webauthn_keys, :account_otp_keys, :account_recovery_codes, :account_sms_codes].each do |t|
        DB[t].count.must_equal 0
      end
    end
  end
end
