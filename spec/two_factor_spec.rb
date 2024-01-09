require_relative 'spec_helper'

require 'rotp'

describe 'Rodauth two factor feature' do
  secret_length = (ROTP::Base32.respond_to?(:random_base32) ? ROTP::Base32.random_base32 : ROTP::Base32.random).length

  def reset_otp_last_use
    DB[:account_otp_keys].update(:last_use=>Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, :seconds=>600))
  end

  it "should allow two factor authentication setup, login, recovery, removal" do
    sms_phone = sms_message = nil
    hmac_secret = '123'
    hmac_old_secret = nil
    old_secret_used = false
    rodauth do
      enable :login, :logout, :otp, :recovery_codes, :sms_codes
      hmac_secret do
        hmac_secret
      end
      hmac_old_secret do
        hmac_old_secret
      end
      otp_valid_code_for_old_secret do
        raise if old_secret_used
        old_secret_used = true
      end

      sms_send do |phone, msg|
        proc{super(phone, msg)}.must_raise NotImplementedError
        sms_phone = phone
        sms_message = msg
      end
      sms_remove_failures do
        if super() == 1
          sms[sms_failures_column].must_equal 0
          sms.fetch(sms_code_column).must_be_nil
        end
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
      page.find('#error_flash').text.must_equal 'This account has not been setup for multifactor authentication'
      page.current_path.must_equal '/otp-setup'
    end

    page.title.must_equal 'Setup TOTP Authentication'
    page.html.must_include '<svg' 
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'asdf'
    click_button 'Setup TOTP Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up TOTP authentication'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>"asdf"
    click_button 'Setup TOTP Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up TOTP authentication'
    page.html.must_include 'Invalid authentication code'

    hmac_secret = "321"
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup TOTP Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up TOTP authentication'

    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup TOTP Authentication'
    page.find('#notice_flash').text.must_equal 'TOTP authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'With 2FA'

    logout
    login
    page.current_path.must_equal '/otp-auth'

    page.find_by_id('otp-auth-code')[:autocomplete].must_equal 'off'

    %w'/otp-disable /recovery-codes /otp-setup /sms-setup /sms-disable /sms-confirm'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'You need to authenticate via an additional factor before continuing'
      page.current_path.must_equal '/multifactor-auth'
    end

    page.title.must_equal 'Authenticate Using Additional Factor'
    click_link 'Authenticate Using TOTP'
    page.title.must_equal 'Enter Authentication Code'
    fill_in 'Authentication Code', :with=>"asdf"
    click_button 'Authenticate Using TOTP'
    page.find('#error_flash').text.must_equal 'Error logging in via TOTP authentication'
    page.html.must_include 'Invalid authentication code'

    fill_in 'Authentication Code', :with=>"#{totp.now[0..2]} #{totp.now[3..-1]}"
    click_button 'Authenticate Using TOTP'
    page.find('#error_flash').text.must_equal 'Error logging in via TOTP authentication'
    page.html.must_include 'Invalid authentication code'
    reset_otp_last_use

    hmac_secret = '123'
    fill_in 'Authentication Code', :with=>"#{totp.now[0..2]} #{totp.now[3..-1]}"
    click_button 'Authenticate Using TOTP'
    page.find('#error_flash').text.must_equal 'Error logging in via TOTP authentication'
    page.html.must_include 'Invalid authentication code'
    reset_otp_last_use

    hmac_secret = '124'
    hmac_old_secret = '125'
    fill_in 'Authentication Code', :with=>"#{totp.now[0..2]} #{totp.now[3..-1]}"
    click_button 'Authenticate Using TOTP'
    page.find('#error_flash').text.must_equal 'Error logging in via TOTP authentication'
    page.html.must_include 'Invalid authentication code'
    reset_otp_last_use

    otp_auth_path = page.current_path
    visit otp_auth_path
    old_secret_used.must_equal false
    hmac_secret = '333'
    hmac_old_secret = '321'
    fill_in 'Authentication Code', :with=>"#{totp.now[0..2]} #{totp.now[3..-1]}"
    click_button 'Authenticate Using TOTP'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    page.html.must_include 'With 2FA'
    old_secret_used.must_equal true
    reset_otp_last_use

    logout
    login
    visit otp_auth_path
    hmac_secret = '321'
    hmac_old_secret = nil
    fill_in 'Authentication Code', :with=>"#{totp.now[0..2]} #{totp.now[3..-1]}"
    click_button 'Authenticate Using TOTP'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    page.html.must_include 'With 2FA'
    reset_otp_last_use

    visit '/otp-setup'
    page.find('#error_flash').text.must_equal 'You have already setup TOTP authentication'

    %w'/otp-auth /recovery-auth /sms-request /sms-auth'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'You have already been multifactor authenticated'
    end

    visit '/sms-disable'
    page.find('#error_flash').text.must_equal 'SMS authentication has not been setup yet'

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
    page.find('#notice_flash').text.must_equal 'SMS authentication needs confirmation'
    sms_phone.must_equal '1234567890'
    sms_message.must_match(/\ASMS confirmation code for www\.example\.com is \d{12}\z/)

    page.title.must_equal 'Confirm SMS Backup Number'
    fill_in 'SMS Code', :with=>"asdf"
    click_button 'Confirm SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Invalid or out of date SMS confirmation code used, must setup SMS authentication again'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'

    visit '/sms-setup'
    page.find('#error_flash').text.must_equal 'SMS authentication needs confirmation'
    page.title.must_equal 'Confirm SMS Backup Number'

    DB[:account_sms_codes].update(:code_issued_at=>Time.now - 310)
    sms_code = sms_message[/\d{12}\z/]
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Invalid or out of date SMS confirmation code used, must setup SMS authentication again'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'
    sms_code = sms_message[/\d{12}\z/]
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'
    page.find('#notice_flash').text.must_equal 'SMS authentication has been setup'

    %w'/sms-setup /sms-confirm'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'SMS authentication has already been setup'
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
    page.find('#error_flash').text.must_equal 'Error authenticating via SMS code'

    DB[:account_sms_codes].update(:code_issued_at=>Time.now - 310)
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Authenticate via SMS Code'
    page.find('#error_flash').text.must_equal 'No current SMS code for this account'

    click_button 'Send SMS Code'
    sms_code = sms_message[/\d{6}\z/]
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Authenticate via SMS Code'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'

    logout
    login

    visit '/sms-request'
    click_button 'Send SMS Code'

    5.times do
      click_button 'Authenticate via SMS Code'
      page.find('#error_flash').text.must_equal 'Error authenticating via SMS code'
      page.current_path.must_equal '/sms-auth'
    end

    click_button 'Authenticate via SMS Code'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out'
    page.current_path.must_equal '/multifactor-auth'

    visit '/sms-request'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out'
    page.current_path.must_equal '/multifactor-auth'

    click_link 'Authenticate Using TOTP'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate Using TOTP'

    visit '/sms-disable'
    page.title.must_equal 'Disable Backup SMS Authentication'
    fill_in 'Password', :with=>'012345678'
    click_button 'Disable Backup SMS Authentication'
    page.find('#error_flash').text.must_equal 'Error disabling SMS authentication'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'Disable Backup SMS Authentication'
    page.find('#notice_flash').text.must_equal 'SMS authentication has been disabled'
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
    page.find('#error_flash').text.must_equal 'Unable to view recovery codes'
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
      click_button 'Authenticate Using TOTP'
      page.find('#error_flash').text.must_equal 'Error logging in via TOTP authentication'
      page.html.must_include 'Invalid authentication code'
    end

    page.title.must_equal 'Enter Authentication Code'
    fill_in 'Authentication Code', :with=>"asdf"
    click_button 'Authenticate Using TOTP'
    page.find('#error_flash').text.must_equal 'TOTP authentication code use locked out due to numerous failures'

    click_link "Authenticate Using SMS Code"
    click_button 'Send SMS Code'

    5.times do
      click_button 'Authenticate via SMS Code'
      page.find('#error_flash').text.must_equal 'Error authenticating via SMS code'
    end

    click_button 'Authenticate via SMS Code'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out'

    page.title.must_equal 'Enter Authentication Recovery Code'
    fill_in 'Recovery Code', :with=>"asdf"
    click_button 'Authenticate via Recovery Code'
    page.find('#error_flash').text.must_equal 'Error authenticating via recovery code'
    page.html.must_include 'Invalid recovery code'

    fill_in 'Recovery Code', :with=>recovery_code
    click_button 'Authenticate via Recovery Code'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    page.html.must_include 'With 2FA'

    visit '/recovery-codes'
    fill_in 'Password', :with=>'0123456789'
    click_button 'View Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    page.html.wont_include(recovery_code)
    find('#recovery-codes').text.split.length.must_equal 15

    click_button 'Add Authentication Recovery Codes'
    page.find('#error_flash').text.must_equal 'Unable to add recovery codes'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'View Authentication Recovery Codes'
    find('#recovery-codes').text.split.length.must_equal 15
    fill_in 'Password', :with=>'0123456789'
    click_button 'Add Authentication Recovery Codes'
    page.find('#notice_flash').text.must_equal 'Additional authentication recovery codes have been added'
    find('#recovery-codes').text.split.length.must_equal 16
    page.html.wont_include('Add Additional Authentication Recovery Codes')

    visit '/otp-disable'
    fill_in 'Password', :with=>'012345678'
    click_button 'Disable TOTP Authentication'
    page.find('#error_flash').text.must_equal 'Error disabling TOTP authentication'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'Disable TOTP Authentication'
    page.find('#notice_flash').text.must_equal 'TOTP authentication has been disabled'
    page.html.must_include 'With 2FA'
    DB[:account_otp_keys].count.must_equal 0
  end

  it "should allow namespaced two factor authentication without password requirements" do
    rodauth do
      enable :login, :logout, :otp, :recovery_codes
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
      page.find('#error_flash').text.must_equal 'This account has not been setup for multifactor authentication'
      page.current_path.must_equal '/auth/otp-setup'
    end

    page.title.must_equal 'Setup TOTP Authentication'
    page.html.must_include '<svg' 
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret, :digits=>8)
    fill_in 'Authentication Code', :with=>"asdf"
    click_button 'Setup TOTP Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up TOTP authentication'
    page.html.must_include 'Invalid authentication code'

    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup TOTP Authentication'
    page.find('#notice_flash').text.must_equal 'TOTP authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'With 2FA'
    reset_otp_last_use

    visit '/auth/logout'
    click_button 'Logout'
    login(:visit=>false)

    page.current_path.must_equal '/auth/otp-auth'

    %w'/auth/otp-disable /auth/recovery-codes /auth/otp-setup'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'You need to authenticate via an additional factor before continuing'
      page.current_path.must_equal '/auth/otp-auth'
    end

    page.title.must_equal 'Enter Authentication Code'
    fill_in 'Authentication Code', :with=>"asdf"
    click_button 'Authenticate Using TOTP'
    page.find('#error_flash').text.must_equal 'Error logging in via TOTP authentication'
    page.html.must_include 'Invalid authentication code'

    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate Using TOTP'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    page.html.must_include 'With 2FA'
    reset_otp_last_use

    visit '/auth/otp-auth'
    page.find('#error_flash').text.must_equal 'You have already been multifactor authenticated'

    visit '/auth/otp-setup'
    page.find('#error_flash').text.must_equal 'You have already setup TOTP authentication'

    visit '/auth/recovery-auth'
    page.find('#error_flash').text.must_equal 'You have already been multifactor authenticated'

    visit '/auth/recovery-codes'
    page.title.must_equal 'View Authentication Recovery Codes'
    click_button 'View Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    find('#recovery-codes').text.split.length.must_equal 0

    click_button 'Add Authentication Recovery Codes'
    page.find('#notice_flash').text.must_equal 'Additional authentication recovery codes have been added'
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
      click_button 'Authenticate Using TOTP'
      page.find('#error_flash').text.must_equal 'Error logging in via TOTP authentication'
      page.html.must_include 'Invalid authentication code'
    end

    page.title.must_equal 'Enter Authentication Code'
    fill_in 'Authentication Code', :with=>"asdf"
    click_button 'Authenticate Using TOTP'

    page.find('#error_flash').text.must_equal 'TOTP authentication code use locked out due to numerous failures'
    page.title.must_equal 'Enter Authentication Recovery Code'
    fill_in 'Recovery Code', :with=>"asdf"
    click_button 'Authenticate via Recovery Code'
    page.find('#error_flash').text.must_equal 'Error authenticating via recovery code'
    page.html.must_include 'Invalid recovery code'
    fill_in 'Recovery Code', :with=>recovery_code
    click_button 'Authenticate via Recovery Code'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    page.html.must_include 'With 2FA'

    visit '/auth/recovery-codes'
    click_button 'View Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    page.html.wont_include(recovery_code)
    find('#recovery-codes').text.split.length.must_equal 15
    click_button 'Add Authentication Recovery Codes'
    page.find('#notice_flash').text.must_equal 'Additional authentication recovery codes have been added'
    find('#recovery-codes').text.split.length.must_equal 16
    page.html.wont_include('Add Additional Authentication Recovery Codes')

    visit '/auth/otp-disable'
    click_button 'Disable TOTP Authentication'
    page.find('#notice_flash').text.must_equal 'TOTP authentication has been disabled'
    page.html.must_include 'With 2FA'
    DB[:account_otp_keys].count.must_equal 0
  end

  it "should require login and OTP authentication to perform certain actions if user signed up for OTP" do
    rodauth do
      enable :login, :logout, :change_password, :change_login, :close_account, :otp
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
    click_button 'Setup TOTP Authentication'
    page.current_path.must_equal '/'

    logout
    login

    %w'/change-password /change-login /close-account /a'.each do |path|
      visit path
      page.current_path.must_equal '/otp-auth'
    end

    reset_otp_last_use
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate Using TOTP'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    page.html.must_include 'bbb'

    visit '/otp-disable'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Disable TOTP Authentication'
    page.find('#notice_flash').text.must_equal 'TOTP authentication has been disabled'
    page.html.must_include 'bbb'
    visit 'a'
    page.html.must_include 'aaa'
  end

  it "should allow returning to requested location when two factor auth was required" do
    rodauth do
      enable :login, :logout, :otp, :jwt
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
    click_button 'Setup TOTP Authentication'
    page.find('#notice_flash').text.must_equal 'TOTP authentication is now setup'

    logout
    reset_otp_last_use
    login

    visit '/page?foo=bar'
    page.current_path.must_equal '/otp-auth'

    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate Using TOTP'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    page.html.must_include "Passed Authentication Required: bar"
  end

  it "should handle attempts to insert a duplicate recovery code" do
    keys = ['a', 'a', 'b']
    interval = 1000000
    rodauth do
      enable :login, :logout, :otp, :recovery_codes, :jwt
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
    click_button 'Setup TOTP Authentication'
    page.find('#notice_flash').text.must_equal 'TOTP authentication is now setup'
    page.current_path.must_equal '/'

    visit '/recovery-codes'
    fill_in 'Password', :with=>'0123456789'
    click_button 'View Authentication Recovery Codes'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Add Authentication Recovery Codes'

    DB[:account_recovery_codes].select_order_map(:code).must_equal ['a', 'b']
  end

  it "should handle two factor lockout when using rodauth.require_two_factor_setup and rodauth.require_authentication" do
    drift = nil
    rodauth do
      enable :login, :logout, :otp
      otp_drift do
        drift
      end
    end
    roda do |r|
      r.rodauth
      r.get('use2'){rodauth.uses_two_factor_authentication?.inspect}
      rodauth.require_authentication
      rodauth.require_two_factor_setup

      view :content=>"Logged in"
    end

    visit '/use2'
    page.body.must_equal 'false'

    login

    visit '/use2'
    page.body.must_equal 'false'

    visit '/otp-setup'
    page.title.must_equal 'Setup TOTP Authentication'
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.at(Time.now - 60)
    click_button 'Setup TOTP Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up TOTP authentication'

    drift = 30
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup TOTP Authentication'
    page.find('#notice_flash').text.must_equal 'TOTP authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged in'
    reset_otp_last_use

    visit '/use2'
    page.body.must_equal 'true'

    logout
    login

    6.times do
      page.title.must_equal 'Enter Authentication Code'
      fill_in 'Authentication Code', :with=>'foo'
      click_button 'Authenticate Using TOTP'
    end
    page.find('#error_flash').text.must_equal 'TOTP authentication code use locked out due to numerous failures'
    page.title.must_equal 'Authenticate Using Additional Factor'
  end

  it "should handle deleted account when checking rodauth.two_factor_authentication_setup?" do
    rodauth do
      enable :login, :logout, :two_factor_base
      account_password_hash_column :ph
    end
    roda do |r|
      r.rodauth
      r.get('setup'){rodauth.two_factor_authentication_setup?.inspect}
      ""
    end

    visit '/setup'
    page.body.must_equal 'false'

    login
    visit '/setup'
    page.body.must_equal 'false'

    DB[PASSWORD_HASH_TABLE].delete
    DB[:accounts].delete
    visit '/setup'
    page.body.must_equal 'false'
  end

  it "should allow two factor authentication setup, login, removal without recovery" do
    rodauth do
      enable :login, :logout, :otp
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
    page.title.must_equal 'Setup TOTP Authentication'
    page.html.must_include '<svg' 
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup TOTP Authentication'
    page.find('#notice_flash').text.must_equal 'TOTP authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'With OTP'
    reset_otp_last_use

    logout
    login

    visit '/otp-auth'
    6.times do
      page.title.must_equal 'Enter Authentication Code'
      fill_in 'Authentication Code', :with=>'foo'
      click_button 'Authenticate Using TOTP'
    end
    page.find('#error_flash').text.must_equal 'TOTP authentication code use locked out due to numerous failures'
    page.body.must_include 'OTP Locked Out'
    page.current_path.must_equal '/'
    DB[:account_otp_keys].update(:num_failures=>0)

    visit '/otp-auth'
    page.title.must_equal 'Enter Authentication Code'
    page.html.wont_include 'Authenticate using recovery code'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate Using TOTP'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    page.html.must_include 'With OTP'

    visit '/otp-disable'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Disable TOTP Authentication'
    page.find('#notice_flash').text.must_equal 'TOTP authentication has been disabled'
    page.html.must_include 'Without OTP'
    DB[:account_otp_keys].count.must_equal 0
  end

  [true, false].each do |before|
    it "should remove multifactor authentication information when closing accounts, when loading close_account #{before ? "before" : "after"}" do
      rodauth do
        features = [:otp, :recovery_codes, :sms_codes, :close_account]
        features.reverse! if before
        enable :login, :logout, *features
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
      click_button 'Setup TOTP Authentication'

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
      page.find('#error_flash').text.must_equal 'This account has not been setup for multifactor authentication'
      page.current_path.must_equal '/sms-setup'
    end

    %w'/sms-disable /sms-request /sms-auth'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'SMS authentication has not been setup yet'
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
    page.find('#notice_flash').text.must_equal 'SMS authentication needs confirmation'
    sms_phone.must_equal '1234567890'
    sms_message.must_match(/\ASMS confirmation code for www\.example\.com is \d{12}\z/)

    page.title.must_equal 'Confirm SMS Backup Number'
    fill_in 'SMS Code', :with=>"asdf"
    click_button 'Confirm SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Invalid or out of date SMS confirmation code used, must setup SMS authentication again'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'

    visit '/sms-setup'
    page.find('#error_flash').text.must_equal 'SMS authentication needs confirmation'
    page.title.must_equal 'Confirm SMS Backup Number'

    DB[:account_sms_codes].update(:code_issued_at=>Time.now - 310)
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Invalid or out of date SMS confirmation code used, must setup SMS authentication again'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'
    page.find('#notice_flash').text.must_equal "SMS authentication has been setup"

    visit '/recovery-codes'
    page.title.must_equal 'View Authentication Recovery Codes'
    fill_in 'Password', :with=>'012345678'
    click_button 'View Authentication Recovery Codes'
    page.find('#error_flash').text.must_equal 'Unable to view recovery codes'
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
      page.find('#error_flash').text.must_equal 'You need to authenticate via an additional factor before continuing'
      page.current_path.must_equal '/multifactor-auth'
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
    page.find('#error_flash').text.must_equal 'Error authenticating via SMS code'

    DB[:account_sms_codes].update(:code_issued_at=>Time.now - 310)
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Authenticate via SMS Code'
    page.find('#error_flash').text.must_equal 'No current SMS code for this account'

    click_button 'Send SMS Code'
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Authenticate via SMS Code'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'

    %w'/recovery-auth /sms-request /sms-auth'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'You have already been multifactor authenticated'
    end

    %w'/sms-setup /sms-confirm'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'SMS authentication has already been setup'
      page.current_path.must_equal '/'
    end

    logout
    login

    click_button 'Send SMS Code'

    5.times do
      click_button 'Authenticate via SMS Code'
      page.find('#error_flash').text.must_equal 'Error authenticating via SMS code'
      page.current_path.must_equal '/sms-auth'
    end

    click_button 'Authenticate via SMS Code'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out'
    page.current_path.must_equal '/recovery-auth'

    visit '/sms-request'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out'
    page.current_path.must_equal '/recovery-auth'

    page.title.must_equal 'Enter Authentication Recovery Code'
    fill_in 'Recovery Code', :with=>"asdf"
    click_button 'Authenticate via Recovery Code'
    page.find('#error_flash').text.must_equal 'Error authenticating via recovery code'
    page.html.must_include 'Invalid recovery code'

    fill_in 'Recovery Code', :with=>recovery_code
    click_button 'Authenticate via Recovery Code'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    page.html.must_include 'With OTP'

    visit '/recovery-codes'
    fill_in 'Password', :with=>'0123456789'
    click_button 'View Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    page.html.wont_include(recovery_code)
    find('#recovery-codes').text.split.length.must_equal 15

    click_button 'Add Authentication Recovery Codes'
    page.find('#error_flash').text.must_equal 'Unable to add recovery codes'
    page.html.must_include 'invalid password'

    visit '/sms-disable'
    page.title.must_equal 'Disable Backup SMS Authentication'
    fill_in 'Password', :with=>'012345678'
    click_button 'Disable Backup SMS Authentication'
    page.find('#error_flash').text.must_equal 'Error disabling SMS authentication'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'Disable Backup SMS Authentication'
    page.find('#notice_flash').text.must_equal 'SMS authentication has been disabled'
    page.current_path.must_equal '/'

    DB[:account_sms_codes].count.must_equal 0
  end

  it "should have recovery_codes work when used by itself" do
    rodauth do
      enable :login, :logout, :recovery_codes
      json_response_success_key nil
    end
    roda(:json_html) do |r|
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
    page.find('#error_flash').text.must_equal 'This account has not been setup for multifactor authentication'
    page.current_path.must_equal '/recovery-codes'

    page.title.must_equal 'View Authentication Recovery Codes'
    fill_in 'Password', :with=>'012345678'
    click_button 'View Authentication Recovery Codes'
    page.find('#error_flash').text.must_equal 'Unable to view recovery codes'
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
    recovery_code = recovery_codes.shift

    logout
    login
    page.current_path.must_equal '/recovery-auth'

    visit '/recovery-codes'
    page.find('#error_flash').text.must_equal 'You need to authenticate via an additional factor before continuing'
    page.current_path.must_equal '/recovery-auth'

    page.title.must_equal 'Enter Authentication Recovery Code'
    fill_in 'Recovery Code', :with=>"asdf"
    click_button 'Authenticate via Recovery Code'
    page.find('#error_flash').text.must_equal 'Error authenticating via recovery code'
    page.html.must_include 'Invalid recovery code'

    fill_in 'Recovery Code', :with=>recovery_code
    click_button 'Authenticate via Recovery Code'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    page.html.must_include 'With OTP'

    visit '/recovery-codes'
    fill_in 'Password', :with=>'0123456789'
    click_button 'View Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    page.html.wont_include(recovery_code)
    page.html.wont_include('Add Authentication Recovery Codes')
    recovery_codes = find('#recovery-codes').text.split
    recovery_codes.length.must_equal 16
    recovery_code = recovery_codes.shift

    logout
    json_login(:no_check=>true)
    res = json_request('/recovery-auth', 'recovery-code'=>recovery_code)
    res.must_equal [200, {}]
    res = json_request('/recovery-codes', :password=>'0123456789')
    res[1].delete('codes').must_include recovery_codes.first
    res.must_equal [200, {}]
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
      page.find('#error_flash').text.must_equal 'SMS authentication has not been setup yet'
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
    page.find('#notice_flash').text.must_equal 'SMS authentication needs confirmation'
    sms_phone.must_equal '1234567890'
    sms_message.must_match(/\ASMS confirmation code for www\.example\.com is \d{12}\z/)

    page.title.must_equal 'Confirm SMS Backup Number'
    fill_in 'SMS Code', :with=>"asdf"
    click_button 'Confirm SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Invalid or out of date SMS confirmation code used, must setup SMS authentication again'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'

    visit '/sms-setup'
    page.find('#error_flash').text.must_equal 'SMS authentication needs confirmation'
    page.title.must_equal 'Confirm SMS Backup Number'

    DB[:account_sms_codes].update(:code_issued_at=>Time.now - 310)
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Invalid or out of date SMS confirmation code used, must setup SMS authentication again'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'
    page.find('#notice_flash').text.must_equal "SMS authentication has been setup"

    logout
    login
    page.current_path.must_equal '/sms-request'

    %w'/sms-setup /sms-disable /sms-confirm'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'You need to authenticate via an additional factor before continuing'
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
    page.find('#error_flash').text.must_equal 'Error authenticating via SMS code'

    DB[:account_sms_codes].update(:code_issued_at=>Time.now - 310)
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Authenticate via SMS Code'
    page.find('#error_flash').text.must_equal 'No current SMS code for this account'

    click_button 'Send SMS Code'
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Authenticate via SMS Code'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'

    %w'/sms-request /sms-auth'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'You have already been multifactor authenticated'
    end

    %w'/sms-setup /sms-confirm'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'SMS authentication has already been setup'
      page.current_path.must_equal '/'
    end

    logout
    login

    click_button 'Send SMS Code'

    5.times do
      click_button 'Authenticate via SMS Code'
      page.find('#error_flash').text.must_equal 'Error authenticating via SMS code'
      page.current_path.must_equal '/sms-auth'
    end

    click_button 'Authenticate via SMS Code'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out'
    page.current_path.must_equal '/multifactor-auth'

    visit '/'
    page.body.must_include "With SMS Locked Out"

    visit '/sms-request'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out'
    page.current_path.must_equal '/multifactor-auth'

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
    page.find('#notice_flash').text.must_equal 'SMS authentication has been disabled'
    page.current_path.must_equal '/'

    DB[:account_sms_codes].count.must_equal 0
  end

  [:jwt, :json].each do |json|
    it "should allow two factor authentication via #{json}" do
      hmac_secret = sms_phone = sms_message = sms_code = nil
      success_key = 'success'
      rodauth do
        enable :login, :logout, :otp, :recovery_codes, :sms_codes
        hmac_secret do
          hmac_secret
        end
        sms_send do |phone, msg|
          sms_phone = phone
          sms_message = msg
          sms_code = msg[/\d+\z/]
        end
        json_response_success_key do
          success_key
        end
      end
      roda(json) do |r|
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

      success_key = nil
      res = json_request('/multifactor-manage')
      res.must_equal [200, {'setup_links'=>%w'/otp-setup', 'remove_links'=>[]}] 
      success_key = 'success'

      res = json_request('/multifactor-auth')
      res.must_equal [403, {"reason"=>"two_factor_not_setup", "error"=>"This account has not been setup for multifactor authentication"}]

      %w'/otp-disable /recovery-auth /recovery-codes /sms-setup /sms-confirm /otp-auth'.each do |path|
        json_request(path).must_equal [403, {'reason' => 'two_factor_not_setup', 'error'=>'This account has not been setup for multifactor authentication'}]
      end
      %w'/sms-disable /sms-request /sms-auth'.each do |path|
        json_request(path).must_equal [403, {'reason' => 'sms_not_setup', 'error'=>'SMS authentication has not been setup yet'}]
      end

      secret = (ROTP::Base32.respond_to?(:random_base32) ? ROTP::Base32.random_base32 : ROTP::Base32.random).downcase
      totp = ROTP::TOTP.new(secret)

      res = json_request('/otp-setup', :password=>'123456', :otp_secret=>secret)
      res.must_equal [401, {'reason'=>"invalid_password",'error'=>'Error setting up TOTP authentication', "field-error"=>["password", 'invalid password']}] 

      res = json_request('/otp-setup', :password=>'0123456789', :otp=>'adsf', :otp_secret=>secret)
      res.must_equal [401, {'reason'=>"invalid_otp_auth_code",'error'=>'Error setting up TOTP authentication', "field-error"=>["otp", 'Invalid authentication code']}] 

      res = json_request('/otp-setup', :password=>'0123456789', :otp=>'adsf', :otp_secret=>'asdf')
      res.must_equal [422, {'reason'=>"invalid_otp_secret",'error'=>'Error setting up TOTP authentication', "field-error"=>["otp_secret", 'invalid secret']}] 

      res = json_request('/otp-setup', :password=>'0123456789', :otp=>totp.now, :otp_secret=>secret)
      res.must_equal [200, {'success'=>'TOTP authentication is now setup'}]
      reset_otp_last_use

      res = json_request('/multifactor-manage')
      res.must_equal [200, {'setup_links'=>%w'/sms-setup /recovery-codes', 'remove_links'=>%w'/otp-disable', "success"=>""}] 

      json_logout
      json_login
      json_request.must_equal [200, [2]]

      res = json_request('/multifactor-manage')
      res.must_equal [401, {"reason"=>"two_factor_need_authentication", "error"=>"You need to authenticate via an additional factor before continuing"}]

      success_key = nil
      res = json_request('/multifactor-auth')
      res.must_equal [200, {'auth_links'=>%w'/otp-auth'}] 
      success_key = 'success'

      %w'/otp-disable /recovery-codes /otp-setup /sms-setup /sms-disable /sms-confirm'.each do |path|
        json_request(path).must_equal [401, {'reason'=>'two_factor_need_authentication', 'error'=>'You need to authenticate via an additional factor before continuing'}]
      end

      res = json_request('/otp-auth', :otp=>'adsf')
      res.must_equal [401, {'reason'=>"invalid_otp_auth_code",'error'=>'Error logging in via TOTP authentication', "field-error"=>["otp", 'Invalid authentication code']}] 

      res = json_request('/otp-auth', :otp=>totp.now)
      res.must_equal [200, {'success'=>'You have been multifactor authenticated'}]
      json_request.must_equal [200, [1]]
      reset_otp_last_use

      res = json_request('/otp-setup')
      res.must_equal [400, {'error'=>'You have already setup TOTP authentication'}] 

      %w'/otp-auth /recovery-auth /sms-request /sms-auth'.each do |path|
        res = json_request(path)
        res.must_equal [403, {'reason'=>'two_factor_already_authenticated', 'error'=>'You have already been multifactor authenticated'}] 
      end

      res = json_request('/sms-disable')
      res.must_equal [403, {'reason'=>'sms_not_setup', 'error'=>'SMS authentication has not been setup yet'}] 

      res = json_request('/sms-setup', :password=>'012345678', "sms-phone"=>'(123) 456')
      res.must_equal [401, {'reason'=>"invalid_password",'error'=>'Error setting up SMS authentication', "field-error"=>["password", 'invalid password']}] 

      res = json_request('/sms-setup', :password=>'0123456789', "sms-phone"=>'(123) 456')
      res.must_equal [422, {'reason'=>"invalid_phone_number",'error'=>'Error setting up SMS authentication', "field-error"=>["sms-phone", 'invalid SMS phone number']}] 

      res = json_request('/sms-setup', :password=>'0123456789', "sms-phone"=>'(123) 4567 890')
      res.must_equal [200, {'success'=>'SMS authentication needs confirmation'}]

      sms_phone.must_equal '1234567890'
      sms_message.must_match(/\ASMS confirmation code for example\.com:? is \d{12}\z/)

      res = json_request('/sms-confirm', :sms_code=>'asdf')
      res.must_equal [401, {'reason'=>'invalid_sms_confirmation_code', 'error'=>'Invalid or out of date SMS confirmation code used, must setup SMS authentication again'}] 

      res = json_request('/sms-setup', :password=>'0123456789', "sms-phone"=>'(123) 4567 890')
      res.must_equal [200, {'success'=>'SMS authentication needs confirmation'}]

      DB[:account_sms_codes].update(:code_issued_at=>Time.now - 310)
      res = json_request('/sms-confirm', :sms_code=>sms_code)
      res.must_equal [401, {'reason'=>'invalid_sms_confirmation_code', 'error'=>'Invalid or out of date SMS confirmation code used, must setup SMS authentication again'}] 

      res = json_request('/sms-setup', :password=>'0123456789', "sms-phone"=>'(123) 4567 890')
      res.must_equal [200, {'success'=>'SMS authentication needs confirmation'}]

      res = json_request('/sms-confirm', "sms-code"=>sms_code)
      res.must_equal [200, {'success'=>'SMS authentication has been setup'}]

      %w'/sms-setup /sms-confirm'.each do |path|
        res = json_request(path)
        res.must_equal [403, {'reason'=>'sms_already_setup', 'error'=>'SMS authentication has already been setup'}] 
      end

      res = json_request('/multifactor-manage')
      res.must_equal [200, {'setup_links'=>%w'/recovery-codes', 'remove_links'=>%w'/otp-disable /sms-disable', "success"=>""}] 

      res = json_request('/multifactor-auth')
      res.must_equal [403, {"reason"=>"two_factor_already_authenticated", "error"=>"You have already been multifactor authenticated"}]

      json_logout
      json_login

      res = json_request('/multifactor-auth')
      res.must_equal [200, {'auth_links'=>%w'/otp-auth /sms-request', "success"=>""}] 

      res = json_request('/sms-auth')
      res.must_equal [401, {'reason'=>"no_current_sms_code", 'error'=>'No current SMS code for this account'}]

      sms_phone = sms_message = nil
      res = json_request('/sms-request')
      res.must_equal [200, {'success'=>'SMS authentication code has been sent'}]
      sms_phone.must_equal '1234567890'
      sms_message.must_match(/\ASMS authentication code for example\.com:? is \d{6}\z/)

      res = json_request('/sms-auth')
      res.must_equal [401, {'reason'=>"invalid_sms_code", 'error'=>'Error authenticating via SMS code', "field-error"=>["sms-code", "invalid SMS code"]}]

      DB[:account_sms_codes].update(:code_issued_at=>Time.now - 310)
      res = json_request('/sms-auth')
      res.must_equal [401, {'reason'=>"no_current_sms_code", 'error'=>'No current SMS code for this account'}]

      res = json_request('/sms-request')
      res.must_equal [200, {'success'=>'SMS authentication code has been sent'}]

      res = json_request('/sms-auth', 'sms-code'=>sms_code)
      res.must_equal [200, {'success'=>'You have been multifactor authenticated'}]
      json_request.must_equal [200, [1]]

      json_logout
      json_login

      res = json_request('/sms-request')
      res.must_equal [200, {'success'=>'SMS authentication code has been sent'}]

      5.times do
        res = json_request('/sms-auth')
        res.must_equal [401, {'reason'=>"invalid_sms_code", 'error'=>'Error authenticating via SMS code', "field-error"=>["sms-code", "invalid SMS code"]}]
      end

      res = json_request('/sms-auth')
      res.must_equal [403, {'reason'=>'sms_locked_out', 'error'=>'SMS authentication has been locked out'}]

      res = json_request('/sms-request')
      res.must_equal [403, {'reason'=>'sms_locked_out', 'error'=>'SMS authentication has been locked out'}]

      res = json_request('/otp-auth', :otp=>totp.now)
      res.must_equal [200, {'success'=>'You have been multifactor authenticated'}]
      json_request.must_equal [200, [1]]

      res = json_request('/sms-disable', :password=>'012345678')
      res.must_equal [401, {'reason'=>"invalid_password", 'error'=>'Error disabling SMS authentication', "field-error"=>["password", 'invalid password']}]

      res = json_request('/sms-disable', :password=>'0123456789')
      res.must_equal [200, {'success'=>'SMS authentication has been disabled'}]

      res = json_request('/sms-setup', :password=>'0123456789', "sms-phone"=>'(123) 4567 890')
      res.must_equal [200, {'success'=>'SMS authentication needs confirmation'}]

      res = json_request('/sms-confirm', "sms-code"=>sms_code)
      res.must_equal [200, {'success'=>'SMS authentication has been setup'}]

      res = json_request('/recovery-codes', :password=>'asdf')
      res.must_equal [401, {'reason'=>"invalid_password", 'error'=>'Unable to view recovery codes', "field-error"=>["password", 'invalid password']}] 

      res = json_request('/recovery-codes', :password=>'0123456789')
      res[1].delete('codes').must_be_empty
      res.must_equal [200, {'success'=>''}]

      res = json_request('/recovery-codes', :password=>'0123456789', :add=>'1')
      codes = res[1].delete('codes')
      codes.sort.must_equal DB[:account_recovery_codes].select_map(:code).sort
      codes.length.must_equal 16
      res.must_equal [200, {'success'=>'Additional authentication recovery codes have been added'}]

      json_logout
      json_login

      5.times do
        res = json_request('/otp-auth', :otp=>'asdf')
        res.must_equal [401, {'reason'=>"invalid_otp_auth_code", 'error'=>'Error logging in via TOTP authentication', "field-error"=>["otp", 'Invalid authentication code']}] 
      end

      res = json_request('/otp-auth', :otp=>'asdf')
      res.must_equal [403, {'reason'=>"otp_locked_out",'error'=>'TOTP authentication code use locked out due to numerous failures'}] 

      res = json_request('/sms-request')
      5.times do
        res = json_request('/sms-auth')
        res.must_equal [401, {'reason'=>"invalid_sms_code", 'error'=>'Error authenticating via SMS code', "field-error"=>["sms-code", "invalid SMS code"]}]
      end

      res = json_request('/otp-auth', :otp=>'asdf')
      res.must_equal [403, {'reason'=>"otp_locked_out", 'error'=>'TOTP authentication code use locked out due to numerous failures'}] 

      res = json_request('/sms-auth')
      res.must_equal [403, {'reason'=>'sms_locked_out', 'error'=>'SMS authentication has been locked out'}] 

      res = json_request('/recovery-auth', 'recovery-code'=>'adsf')
      res.must_equal [401, {'reason'=>"invalid_recovery_code", 'error'=>'Error authenticating via recovery code', "field-error"=>["recovery-code", "Invalid recovery code"]}]

      res = json_request('/recovery-auth', 'recovery-code'=>codes.first)
      res.must_equal [200, {'success'=>'You have been multifactor authenticated'}]
      json_request.must_equal [200, [1]]

      res = json_request('/recovery-codes', :password=>'0123456789')
      codes2 = res[1].delete('codes')
      codes2.sort.must_equal codes[1..-1].sort
      res.must_equal [200, {'success'=>''}]

      res = json_request('/recovery-codes', :password=>'012345678', :add=>'1')
      res.must_equal [401, {'reason'=>"invalid_password", 'error'=>'Unable to add recovery codes', "field-error"=>["password", 'invalid password']}] 

      res = json_request('/recovery-codes', :password=>'0123456789', :add=>'1')
      codes3 = res[1].delete('codes')
      (codes3 - codes2).length.must_equal 1
      res.must_equal [200, {'success'=>'Additional authentication recovery codes have been added'}]

      res = json_request('/otp-disable', :password=>'012345678')
      res.must_equal [401, {'reason'=>"invalid_password", 'error'=>'Error disabling TOTP authentication', "field-error"=>["password", 'invalid password']}] 

      res = json_request('/otp-disable', :password=>'0123456789')
      res.must_equal [200, {'success'=>'TOTP authentication has been disabled'}]

      DB[:account_otp_keys].count.must_equal 0

      hmac_secret  = "123"
      res = json_request('/otp-setup')
      secret = res[1].delete("otp_secret")
      raw_secret = res[1].delete("otp_raw_secret")
      res.must_equal [422, {'reason'=>"invalid_otp_secret",'error'=>'Error setting up TOTP authentication', "field-error"=>["otp_secret", 'invalid secret']}] 

      totp = ROTP::TOTP.new(secret)
      hmac_secret  = "321"
      res = json_request('/otp-setup', :password=>'0123456789', :otp=>totp.now, :otp_secret=>secret, :otp_raw_secret=>raw_secret)
      res.must_equal [422, {'reason'=>"invalid_otp_secret",'error'=>'Error setting up TOTP authentication', "field-error"=>["otp_secret", 'invalid secret']}] 

      reset_otp_last_use
      hmac_secret  = "123"
      res = json_request('/otp-setup', :password=>'0123456789', :otp=>totp.now, :otp_secret=>secret, :otp_raw_secret=>raw_secret)
      res.must_equal [200, {'success'=>'TOTP authentication is now setup'}]
      reset_otp_last_use

      json_logout
      json_login

      hmac_secret  = "321"
      res = json_request('/otp-auth', :otp=>totp.now)
      res.must_equal [401, {'reason'=>"invalid_otp_auth_code",'error'=>'Error logging in via TOTP authentication', "field-error"=>["otp", 'Invalid authentication code']}] 

      hmac_secret  = "123"
      res = json_request('/otp-auth', :otp=>totp.now)
      res.must_equal [200, {'success'=>'You have been multifactor authenticated'}]
      json_request.must_equal [200, [1]]
    end
  end

  it "should call the two factor auth before hook only when setup" do
    before_called = false
    rodauth do
      enable :login, :otp, :logout
      before_otp_auth_route{before_called = true}
      before_otp_setup_route{otp}
    end
    roda do |r|
      r.rodauth
      r.get 'valid', String do |code|
        rodauth.otp_valid_code?(code).to_s
      end

      r.redirect '/login' unless rodauth.logged_in?

      if rodauth.two_factor_authentication_setup?
        r.redirect '/otp-auth' unless rodauth.authenticated?
        view :content=>"With OTP"
      else    
        view :content=>"Without OTP"
      end
    end

    visit '/valid/foo'
    page.body.must_equal 'false'

    login
    page.html.must_include('Without OTP')

    visit '/otp-auth'
    before_called.must_equal false
    page.current_path.must_equal '/otp-setup'

    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup TOTP Authentication'
    page.find('#notice_flash').text.must_equal 'TOTP authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'With OTP'

    logout
    before_called.must_equal false
    login
    page.current_path.must_equal '/otp-auth'
    before_called.must_equal true
  end

  it "should allow for timing out otp authentication using otp_last_use" do
    rodauth do
      enable :login, :otp, :logout
    end
    roda do |r|
      r.rodauth

      r.redirect '/login' unless rodauth.logged_in?

      if rodauth.two_factor_authentication_setup?
        if rodauth.authenticated_by && rodauth.authenticated_by.include?('totp') && rodauth.otp_last_use < Time.now - 3600
          rodauth.authenticated_by.delete('totp')
        end
        rodauth.require_authentication
        view :content=>"With OTP"
      else    
        view :content=>"Without OTP"
      end
    end

    login
    page.html.must_include('Without OTP')

    visit '/otp-auth'
    page.current_path.must_equal '/otp-setup'

    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup TOTP Authentication'
    page.find('#notice_flash').text.must_equal 'TOTP authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'With OTP'

    reset_otp_last_use
    visit '/'
    page.html.must_include 'With OTP'
    page.current_path.must_equal '/'

    DB[:account_otp_keys].update(:last_use=>Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, :seconds=>4600))
    visit '/'
    page.current_path.must_equal '/otp-auth'
  end

  it "should show as user is authenticated when setting up OTP" do
    no_freeze!
    rodauth do
      enable :login, :otp
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

    page.title.must_equal 'Setup TOTP Authentication'
    page.html.must_include 'Is Logged In'
    page.html.must_include 'Is Authenticated'
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup TOTP Authentication'
    page.find('#notice_flash').text.must_equal 'TOTP authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'With OTP'
  end

  it "should not display links for routes that were disabled" do
    otp_auth_route = 'otp-auth'
    otp_setup_route = 'otp-setup'
    otp_disable_route = 'otp-disable'
    recovery_auth_route = 'recovery-auth'
    recovery_codes_route = 'recovery-codes'
    sms_request_route = 'sms-request'
    sms_setup_route = 'sms-setup'
    sms_disable_route = 'sms-disable'
    sms_message = nil
    rodauth do
      enable :login, :logout, :otp, :recovery_codes, :sms_codes
      auto_add_recovery_codes? true
      sms_send { |phone, msg| sms_message = msg }
      otp_auth_route { otp_auth_route }
      otp_setup_route { otp_setup_route }
      otp_disable_route { otp_disable_route }
      recovery_auth_route { recovery_auth_route }
      recovery_codes_route { recovery_codes_route }
      sms_request_route { sms_request_route }
      sms_setup_route { sms_setup_route }
      sms_disable_route { sms_disable_route }
    end
    roda do |r|
      r.rodauth
      r.get('auth-links') { rodauth.two_factor_auth_links.map { |link| link[1] }.to_s }
      r.get('setup-links') { rodauth.two_factor_setup_links.map { |link| link[1] }.to_s }
      r.get('remove-links') { rodauth.two_factor_remove_links.map { |link| link[1] }.to_s }
      r.root{view :content=>"Home"}
    end

    visit '/login'
    fill_in 'Login', :with=>"foo@example.com"
    fill_in 'Password', :with=>"0123456789"
    click_on 'Login'
    page.find('#notice_flash').text.must_equal "You have been logged in"

    otp_setup_route = nil
    visit '/setup-links'
    page.html.must_equal '[]'

    otp_setup_route = 'otp-setup'
    visit '/multifactor-auth'
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_on 'Setup TOTP Authentication'
    page.find('#notice_flash').text.must_equal 'TOTP authentication is now setup'

    recovery_codes_route = nil
    sms_setup_route = nil
    visit '/setup-links'
    page.html.must_equal '[]'

    recovery_codes_route = 'recovery-codes'
    sms_setup_route = 'sms-setup'
    visit '/setup-links'
    page.html.must_equal '["/sms-setup", "/recovery-codes"]'

    visit '/sms-setup'
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'
    page.find('#notice_flash').text.must_equal 'SMS authentication needs confirmation'
    sms_code = sms_message[/\d{12}\z/]
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'
    page.find('#notice_flash').text.must_equal 'SMS authentication has been setup'

    visit '/auth-links'
    page.html.must_equal '["/otp-auth", "/sms-request", "/recovery-auth"]'

    otp_auth_route = nil
    recovery_auth_route = nil
    sms_request_route = nil
    visit '/auth-links'
    page.html.must_equal '[]'

    visit '/remove-links'
    page.html.must_equal '["/otp-disable", "/sms-disable"]'

    otp_disable_route = nil
    sms_disable_route = nil
    visit '/remove-links'
    page.html.must_equal '[]'
  end

  it "should allow using otp via internal requests" do
    rodauth do
      enable :login, :logout, :otp, :internal_request
      hmac_secret '123'
      domain 'example.com'
    end
    roda do |r|
      r.rodauth
      r.redirect '/login' unless rodauth.logged_in?
      r.redirect '/otp-setup' unless rodauth.two_factor_authentication_setup?
      r.redirect '/otp-auth' unless rodauth.two_factor_authenticated?
      view :content=>""
    end

    otp_hash = app.rodauth.otp_setup_params(:account_login=>'foo@example.com')
    otp_hash.length.must_equal 2
    secret, raw_secret = otp_hash.values_at(:otp_setup, :otp_setup_raw)
    totp = ROTP::TOTP.new(secret)

    proc do
      app.rodauth.otp_setup(:account_login=>'foo@example.com', :otp_setup=>secret[0...-1], :otp_setup_raw=>raw_secret, :otp_auth=>totp.now)
    end.must_raise Rodauth::InternalRequestError

    proc do
      app.rodauth.otp_setup(:account_login=>'foo@example.com', :otp_setup=>secret, :otp_setup_raw=>raw_secret[0...-1], :otp_auth=>totp.now)
    end.must_raise Rodauth::InternalRequestError

    proc do
      app.rodauth.otp_setup(:account_login=>'foo@example.com', :otp_setup=>secret, :otp_setup_raw=>raw_secret, :otp_auth=>totp.now[0...-1])
    end.must_raise Rodauth::InternalRequestError

    app.rodauth.otp_setup(:account_login=>'foo@example.com', :otp_setup=>secret, :otp_setup_raw=>raw_secret, :otp_auth=>totp.now).must_be_nil
    reset_otp_last_use

    proc do
      app.rodauth.otp_setup_params(:account_login=>'foo@example.com')
    end.must_raise Rodauth::InternalRequestError

    proc do
      app.rodauth.otp_setup(:account_login=>'foo@example.com', :otp_setup=>secret, :otp_setup_raw=>raw_secret, :otp_auth=>totp.now)
    end.must_raise Rodauth::InternalRequestError

    login
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate Using TOTP'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    reset_otp_last_use

    proc do
      app.rodauth.otp_auth(:account_login=>'foo@example.com', :otp_auth=>totp.now[0...-1])
    end.must_raise Rodauth::InternalRequestError

    app.rodauth.otp_auth(:account_login=>'foo@example.com', :otp_auth=>totp.now).must_be_nil
    reset_otp_last_use

    app.rodauth.valid_otp_auth?(:account_login=>'foo@example.com', :otp_auth=>totp.now[0...-1]).must_equal false
    reset_otp_last_use

    app.rodauth.valid_otp_auth?(:account_login=>'foo@example.com', :otp_auth=>totp.now).must_equal true
    reset_otp_last_use

    app.rodauth.otp_disable(:account_login=>'foo@example.com').must_be_nil

    app.rodauth.valid_otp_auth?(:account_login=>'foo@example.com', :otp_auth=>totp.now[0...-1]).must_equal false

    proc do
      app.rodauth.otp_disable(:account_login=>'foo@example.com')
    end.must_raise Rodauth::InternalRequestError
  end

  it "should allow using otp via internal requests without hmac" do
    rodauth do
      enable :login, :logout, :otp, :internal_request
      domain 'example.com'
    end
    roda do |r|
    end

    otp_hash = app.rodauth.otp_setup_params(:account_login=>'foo@example.com')
    otp_hash.length.must_equal 1
    secret = otp_hash[:otp_setup]
    totp = ROTP::TOTP.new(secret)

    proc do
      app.rodauth.otp_setup(:account_login=>'foo@example.com', :otp_setup=>secret[0...-1], :otp_auth=>totp.now)
    end.must_raise Rodauth::InternalRequestError

    proc do
      app.rodauth.otp_setup(:account_login=>'foo@example.com', :otp_setup=>secret, :otp_auth=>totp.now[0...-1])
    end.must_raise Rodauth::InternalRequestError

    app.rodauth.otp_setup(:account_login=>'foo@example.com', :otp_setup=>secret, :otp_auth=>totp.now).must_be_nil
    reset_otp_last_use

    app.rodauth.valid_otp_auth?(:account_login=>'foo@example.com', :otp_auth=>totp.now).must_equal true
    reset_otp_last_use
  end

  it "should allow using recovery codes via internal requests" do
    rodauth do
      enable :login, :logout, :recovery_codes, :internal_request
      recovery_codes_primary? false
    end
    roda do |r|
      r.rodauth
      r.redirect '/login' unless rodauth.logged_in?
      rodauth.require_two_factor_authenticated
      view :content=>""
    end

    app.rodauth.recovery_codes(:account_login=>'foo@example.com').must_equal []

    recovery_codes = app.rodauth.recovery_codes(:account_login=>'foo@example.com', :add_recovery_codes=>'1')
    recovery_codes.length.must_equal 16

    proc do
      app.rodauth.recovery_auth(:account_login=>'foo@example.com', :recovery_codes=>'foo')
    end.must_raise Rodauth::InternalRequestError

    app.rodauth.recovery_auth(:account_login=>'foo@example.com', :recovery_codes=>recovery_codes.shift).must_be_nil

    app.rodauth.valid_recovery_auth?(:account_login=>'foo@example.com', :recovery_codes=>'foo').must_equal false
    app.rodauth.valid_recovery_auth?(:account_login=>'foo@example.com', :recovery_codes=>recovery_codes.shift).must_equal true

    login

    fill_in 'Recovery Code', :with=>recovery_codes.shift
    click_button 'Authenticate via Recovery Code'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'

    recovery_codes2 = app.rodauth.recovery_codes(:account_login=>'foo@example.com')
    recovery_codes2.sort.must_equal recovery_codes.sort

    recovery_codes3 = app.rodauth.recovery_codes(:account_login=>'foo@example.com', :add_recovery_codes=>'1')
    recovery_codes3.length.must_equal 16
    (recovery_codes & recovery_codes3).length.must_equal 13
  end

  it "should allow using sms codes via internal requests" do
    sms_message = nil
    rodauth do
      enable :login, :logout, :sms_codes, :internal_request
      sms_send do |phone, msg|
        sms_message = msg
      end
      domain 'example.com'
    end
    roda do |r|
      r.rodauth
      rodauth.require_two_factor_authenticated
      view :content=>""
    end

    app.rodauth.sms_setup(:account_login=>'foo@example.com', :sms_phone=>'1112223333').must_be_nil
    sms_message.must_match(/\ASMS confirmation code for example\.com is \d{12}\z/)
    sms_code = sms_message[/\d{12}\z/]

    login
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'
    page.find('#notice_flash').text.must_equal 'SMS authentication has been setup'
    logout

    proc do
      app.rodauth.sms_setup(:account_login=>'foo@example.com', :sms_phone=>'1112224444')
    end.must_raise Rodauth::InternalRequestError

    login
    page.title.must_equal 'Send SMS Code'
    click_button 'Send SMS Code'
    sms_message.must_match(/\ASMS authentication code for example\.com is \d{6}\z/)
    sms_code = sms_message[/\d{6}\z/]

    fill_in 'SMS Code', :with=>sms_code
    click_button 'Authenticate via SMS Code'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    logout

    app.rodauth.sms_disable(:account_login=>'foo@example.com').must_be_nil

    proc do
      app.rodauth.sms_disable(:account_login=>'foo@example.com')
    end.must_raise Rodauth::InternalRequestError

    login
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'
    page.find('#notice_flash').text.must_equal 'SMS authentication needs confirmation'
    sms_message.must_match(/\ASMS confirmation code for example\.com is \d{12}\z/)
    sms_code = sms_message[/\d{12}\z/]
    logout

    app.rodauth.sms_confirm(:account_login=>'foo@example.com', :sms_code=>sms_code).must_be_nil

    proc do
      app.rodauth.sms_confirm(:account_login=>'foo@example.com', :sms_code=>sms_code)
    end.must_raise Rodauth::InternalRequestError

    app.rodauth.sms_request(:account_login=>'foo@example.com').must_be_nil
    sms_message.must_match(/\ASMS authentication code for example\.com is \d{6}\z/)
    sms_code = sms_message[/\d{6}\z/]
    app.rodauth.sms_auth(:account_login=>'foo@example.com', :sms_code=>sms_code).must_be_nil

    login
    page.title.must_equal 'Send SMS Code'
    click_button 'Send SMS Code'
    sms_message.must_match(/\ASMS authentication code for example\.com is \d{6}\z/)
    sms_code = sms_message[/\d{6}\z/]
    logout

    app.rodauth.valid_sms_auth?(:account_login=>'foo@example.com', :sms_code=>sms_code).must_equal true
    app.rodauth.valid_sms_auth?(:account_login=>'foo@example.com', :sms_code=>sms_code).must_equal false
  end

  it "should allow removing all multifactor authentication via internal requests" do
    sms_message = nil
    rodauth do
      enable :otp, :sms_codes, :recovery_codes, :internal_request
      sms_send do |phone, msg|
        sms_message = msg
      end
      domain 'example.com'
    end
    roda do |r|
    end

    otp_hash = app.rodauth.otp_setup_params(:account_login=>'foo@example.com')
    totp = ROTP::TOTP.new(otp_hash[:otp_setup])
    app.rodauth.otp_setup(otp_hash.merge(:account_login=>'foo@example.com', :otp_auth=>totp.now)).must_be_nil

    app.rodauth.sms_setup(:account_login=>'foo@example.com', :sms_phone=>'1112223333').must_be_nil
    sms_message.must_match(/\ASMS confirmation code for example\.com is \d{12}\z/)
    sms_code = sms_message[/\d{12}\z/]
    app.rodauth.sms_confirm(:account_login=>'foo@example.com', :sms_code=>sms_code).must_be_nil
    app.rodauth.sms_request(:account_login=>'foo@example.com').must_be_nil
    sms_message.must_match(/\ASMS authentication code for example\.com is \d{6}\z/)
    sms_code = sms_message[/\d{6}\z/]
    app.rodauth.sms_auth(:account_login=>'foo@example.com', :sms_code=>sms_code).must_be_nil

    recovery_codes = app.rodauth.recovery_codes(:account_login=>'foo@example.com', :add_recovery_codes=>'1')
    app.rodauth.recovery_auth(:account_login=>'foo@example.com', :recovery_codes=>recovery_codes.shift).must_be_nil

    app.rodauth.two_factor_disable(:account_login=>'foo@example.com').must_be_nil
    [:account_otp_keys, :account_recovery_codes, :account_sms_codes].each do |t|
      DB[t].count.must_equal 0
    end
  end

  it "should prevent authentication when logged in via password and MFA was disabled in another session" do
    rodauth do
      enable :login, :otp, :internal_request
      domain 'example.com'
    end
    roda do |r|
      r.rodauth
      rodauth.require_authentication
      r.root { "" }
    end

    otp_hash = app.rodauth.otp_setup_params(:account_login=>'foo@example.com')
    totp = ROTP::TOTP.new(otp_hash[:otp_setup])
    app.rodauth.otp_setup(otp_hash.merge(:account_login=>'foo@example.com', :otp_auth=>totp.now))

    login
    page.find('#error_flash').text.must_equal 'You need to authenticate via an additional factor before continuing'
    page.current_path.must_equal '/otp-auth'

    app.rodauth.otp_disable(account_login: 'foo@example.com')

    # not considered authenticated
    visit '/'
    page.find('#error_flash').text.must_equal 'You need to authenticate via an additional factor before continuing'

    # cannot hijack account by setting up TOTP
    visit '/otp-setup'
    page.find('#error_flash').text.must_equal 'You need to authenticate via an additional factor before continuing'
  end

  it "should not accept pending sms codes when signing in" do
    sms_phone = sms_message = nil
    rodauth do
      enable :login, :logout, :otp, :sms_codes
      sms_codes_primary? true

      sms_send do |phone, msg|
        sms_phone = phone
        sms_message = msg
      end
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
    page.title.must_equal 'Setup TOTP Authentication'
    page.html.must_include '<svg'
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup TOTP Authentication'
    page.find('#notice_flash').text.must_equal 'TOTP authentication is now setup'

    visit '/sms-setup'
    page.title.must_equal 'Setup SMS Backup Number'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'
    page.find('#notice_flash').text.must_equal 'SMS authentication needs confirmation'
    sms_phone.must_equal '1234567890'
    sms_message.must_match(/\ASMS confirmation code for www\.example\.com is \d{12}\z/)

    logout
    login
    reset_otp_last_use
    fill_in 'Authentication Code', :with=>"#{totp.now[0..2]} #{totp.now[3..-1]}"
    click_button 'Authenticate Using TOTP'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    page.html.must_include 'With 2FA'
    reset_otp_last_use

    visit '/sms-setup'
    page.find('#error_flash').text.must_equal 'SMS authentication needs confirmation'
    page.title.must_equal 'Confirm SMS Backup Number'
  end

  it "should automatically clear expired SMS confirm codes" do
    sms_phone = sms_message = nil
    rodauth do
      enable :login, :logout, :sms_codes
      sms_codes_primary? true
      two_factor_modifications_require_password? false

      sms_send do |phone, msg|
        sms_phone = phone
        sms_message = msg
      end
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

    visit '/sms-setup'
    page.title.must_equal 'Setup SMS Backup Number'

    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'
    page.find('#notice_flash').text.must_equal 'SMS authentication needs confirmation'
    sms_phone.must_equal '1234567890'
    sms_message.must_match(/\ASMS confirmation code for www\.example\.com is \d{12}\z/)

    visit '/sms-setup'
    page.current_path.must_equal '/sms-confirm'
    page.find('#error_flash').text.must_equal 'SMS authentication needs confirmation'

    DB[:account_sms_codes].update(:code_issued_at=>Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 90000))
    visit '/sms-setup'
    DB[:account_sms_codes].must_be_empty
    page.current_path.must_equal '/sms-setup'
    fill_in 'Phone Number', :with=>'(123) 456-7891'
    click_button 'Setup SMS Backup Number'
    sms_phone.must_equal '1234567891'
    sms_message =~ /\ASMS confirmation code for www\.example\.com is (\d{12})\z/
    code = $1
    code.wont_be_nil

    page.find('#notice_flash').text.must_equal 'SMS authentication needs confirmation'
    fill_in 'SMS Code', :with=>code
    DB[:account_sms_codes].select_map(:num_failures).must_equal [nil]
    click_button "Confirm SMS Backup Number"
    DB[:account_sms_codes].select_map(:num_failures).must_equal [0]
    page.find('#notice_flash').text.must_equal 'SMS authentication has been setup'
    page.current_path.must_equal '/'
  end

  begin
    require 'webauthn/fake_client'
  rescue LoadError
  else
    [true, false].each do |before|
      it "should automatically remove recovery codes once last MFA method is removed if auto_add_recovery_codes? is set to true, when recovery_codes is loaded #{before ? 'before' : 'after'}" do
        sms_message = nil
        hmac_secret = '123'
        rodauth do
          features = [:otp, :sms_codes, :webauthn, :recovery_codes]
          features.reverse! if before
          enable :login, :logout, *features
          hmac_secret do
            hmac_secret
          end
          sms_codes_primary? true
          sms_send do |phone, msg|
            sms_message = msg
          end
          auto_add_recovery_codes? true
          auto_remove_recovery_codes? true
        end
        first_request = nil
        roda do |r|
          first_request ||= r
      
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
      
        origin = first_request.base_url
        webauthn_client = WebAuthn::FakeClient.new(origin)
      
        DB[:account_recovery_codes].must_be_empty
      
        # Doesn't remove recovery codes after OTP disable with OTP & SMS MFA setup
        visit '/otp-setup'
        secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
        totp = ROTP::TOTP.new(secret)
        fill_in 'Authentication Code', :with=>totp.now
        fill_in 'Password', :with=>'0123456789'
        click_button 'Setup TOTP Authentication'
        page.find('#notice_flash').text.must_equal 'TOTP authentication is now setup'
      
        visit '/sms-setup'
        fill_in 'Password', :with=>'0123456789'
        fill_in 'Phone Number', :with=>'(123) 456-7890'
        click_button 'Setup SMS Backup Number'
        sms_code = sms_message[/\d{12}\z/]
        fill_in 'SMS Code', :with=>sms_code
        click_button 'Confirm SMS Backup Number'
        page.find('#notice_flash').text.must_equal 'SMS authentication has been setup'
      
        DB[:account_otp_keys].wont_be_empty
        DB[:account_sms_codes].wont_be_empty
        DB[:account_recovery_codes].wont_be_empty
      
        visit '/otp-disable'
        fill_in 'Password', :with=>'0123456789'
        click_button 'Disable TOTP Authentication'
      
        DB[:account_otp_keys].must_be_empty
        DB[:account_recovery_codes].wont_be_empty
      
        # Removes recovery codes with only SMS setup
        click_link 'Authenticate Using Recovery Code'
        fill_in 'Recovery Code', :with=>DB[:account_recovery_codes].first[:code]
        click_button 'Authenticate via Recovery Code'
      
        visit '/sms-disable'
        fill_in 'Password', :with=>'0123456789'
        click_button 'Disable Backup SMS Authentication'
      
        DB[:account_sms_codes].must_be_empty
        DB[:account_recovery_codes].must_be_empty
      
        # Doesn't remove recovery codes after WebAuthn disable with WebAuthn & OTP MFA setup
        visit '/webauthn-setup'
        challenge = JSON.parse(page.find('#webauthn-setup-form')['data-credential-options'])['challenge']
        fill_in 'webauthn_setup', :with=>webauthn_client.create(challenge: challenge).to_json
        fill_in 'Password', :with=>'0123456789'
        click_button 'Setup WebAuthn Authentication'
        page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
      
        visit '/otp-setup'
        secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
        totp = ROTP::TOTP.new(secret)
        fill_in 'Authentication Code', :with=>totp.now
        fill_in 'Password', :with=>'0123456789'
        click_button 'Setup TOTP Authentication'
        page.find('#notice_flash').text.must_equal 'TOTP authentication is now setup'
      
        DB[:account_webauthn_keys].wont_be_empty
        DB[:account_otp_keys].wont_be_empty
        DB[:account_recovery_codes].wont_be_empty
      
        visit '/webauthn-remove'
        fill_in 'Password', :with=>'0123456789'
        choose "webauthn-remove-#{ DB[:account_webauthn_keys].first[:webauthn_id] }"
        click_button 'Remove WebAuthn Authenticator'
      
        DB[:account_webauthn_keys].must_be_empty
        DB[:account_recovery_codes].wont_be_empty
      
        # Removes recovery codes with only OTP setup
        visit '/otp-disable'
        fill_in 'Password', :with=>'0123456789'
        click_button 'Disable TOTP Authentication'
      
        DB[:account_otp_keys].must_be_empty
        DB[:account_recovery_codes].must_be_empty
      
        # Doesn't remove recovery codes after SMS disable with SMS & WebAuthn MFA setup
        visit '/sms-setup'
        fill_in 'Password', :with=>'0123456789'
        fill_in 'Phone Number', :with=>'(123) 456-7890'
        click_button 'Setup SMS Backup Number'
        sms_code = sms_message[/\d{12}\z/]
        fill_in 'SMS Code', :with=>sms_code
        click_button 'Confirm SMS Backup Number'
        page.find('#notice_flash').text.must_equal 'SMS authentication has been setup'
      
        visit '/webauthn-setup'
        challenge = JSON.parse(page.find('#webauthn-setup-form')['data-credential-options'])['challenge']
        fill_in 'webauthn_setup', :with=>webauthn_client.create(challenge: challenge).to_json
        fill_in 'Password', :with=>'0123456789'
        click_button 'Setup WebAuthn Authentication'
        page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
      
        DB[:account_sms_codes].wont_be_empty
        DB[:account_webauthn_keys].wont_be_empty
        DB[:account_recovery_codes].wont_be_empty
      
        visit '/sms-disable'
        fill_in 'Password', :with=>'0123456789'
        click_button 'Disable Backup SMS Authentication'
      
        DB[:account_sms_codes].must_be_empty
        DB[:account_recovery_codes].wont_be_empty
      
        # Removes recovery codes with only WebAuthn setup
        visit '/webauthn-remove'
        fill_in 'Password', :with=>'0123456789'
        choose "webauthn-remove-#{ DB[:account_webauthn_keys].first[:webauthn_id] }"
        click_button 'Remove WebAuthn Authenticator'
      
        DB[:account_webauthn_keys].must_be_empty
        DB[:account_recovery_codes].must_be_empty
      end
      
      it "should handle webauthn, otp, sms, and recovery codes in use together, when loading webauthn #{before ? "before" : "after"}" do
        recovery_codes_primary = sms_codes_primary = false
        sms_phone = sms_message = nil
        require_password = false
        rodauth do
          features = [:otp, :sms_codes, :recovery_codes, :webauthn]
          features.reverse! if before
          enable :login, :logout, *features
          hmac_secret '123'
          sms_send do |phone, msg|
            sms_phone = phone
            sms_message = msg
          end
          two_factor_modifications_require_password?{require_password}
          sms_codes_primary?{sms_codes_primary}
          recovery_codes_primary?{recovery_codes_primary}
          before_sms_setup{remove_instance_variable(:@sms)}
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

        %w'/multifactor-auth /multifactor-disable'.each do |path|
          visit path
          page.find('#error_flash').text.must_equal 'This account has not been setup for multifactor authentication'
          page.current_path.must_equal '/multifactor-manage'
        end

        visit '/2'
        page.title.must_equal 'Manage Multifactor Authentication'
        page.html.must_match(/Setup Multifactor Authentication.*Setup WebAuthn Authentication.*Setup TOTP Authentication/m)
        page.html.wont_include 'Remove Multifactor Authentication'
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
        challenge = JSON.parse(page.find('#webauthn-setup-form')['data-credential-options'])['challenge']
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
        challenge = JSON.parse(page.find('#webauthn-auth-form')['data-credential-options'])['challenge']
        fill_in 'webauthn_auth', :with=>webauthn_client1.get(challenge: challenge).to_json
        click_button 'Authenticate Using WebAuthn'
        page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
        page.current_path.must_equal '/'
        page.html.must_include 'With 2nd Factor: webauthn'

        visit '/multifactor-manage'
        page.html.must_match(/Setup Multifactor Authentication.*Setup WebAuthn Authentication.*Setup TOTP Authentication.*Setup Backup SMS Authentication.*View Authentication Recovery Codes.*Remove Multifactor Authentication.*Remove WebAuthn Authenticator/m)

        click_link 'Setup TOTP Authentication'
        secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
        totp = ROTP::TOTP.new(secret)
        fill_in 'Authentication Code', :with=>totp.now
        click_button 'Setup TOTP Authentication'
        page.find('#notice_flash').text.must_equal 'TOTP authentication is now setup'
        page.current_path.must_equal '/'
        page.html.must_include 'With 2nd Factor: webauthn'
        reset_otp_last_use
        
        logout
        login

        page.title.must_equal 'Authenticate Using Additional Factor'
        page.html.must_match(/Authenticate Using WebAuthn.*Authenticate Using TOTP/m)
        page.html.wont_include 'Authenticate Using SMS Code'

        click_link 'Authenticate Using TOTP'
        fill_in 'Authentication Code', :with=>totp.now
        click_button 'Authenticate Using TOTP'
        page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
        page.html.must_include 'With 2nd Factor: totp'
        reset_otp_last_use

        visit '/multifactor-manage'
        page.html.must_match(/Setup Multifactor Authentication.*Setup WebAuthn Authentication.*Setup Backup SMS Authentication.*View Authentication Recovery Codes.*Remove Multifactor Authentication.*Remove WebAuthn Authenticator.*Disable TOTP Authentication/m)
        page.html.wont_include 'Setup TOTP Authentication'

        click_link 'View Authentication Recovery Codes'
        click_button 'View Authentication Recovery Codes'
        click_button 'Add Authentication Recovery Codes'
        page.find('#notice_flash').text.must_equal "Additional authentication recovery codes have been added"
        page.current_path.must_equal '/recovery-codes'

        visit '/multifactor-manage'
        click_link 'Setup WebAuthn Authentication'
        challenge = JSON.parse(page.find('#webauthn-setup-form')['data-credential-options'])['challenge']
        fill_in 'webauthn_setup', :with=>webauthn_client2.create(challenge: challenge).to_json
        click_button 'Setup WebAuthn Authentication'
        page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
        page.current_path.must_equal '/'
        page.html.must_include 'With 2nd Factor: totp'

        visit '/multifactor-manage'
        click_link 'Setup Backup SMS Authentication'
        fill_in 'Phone Number', :with=>'(123) 456-7890'
        click_button 'Setup SMS Backup Number'
        page.find('#notice_flash').text.must_equal 'SMS authentication needs confirmation'
        sms_phone.must_equal '1234567890'
        sms_message.must_match(/\ASMS confirmation code for www\.example\.com is \d{12}\z/)
        sms_code = sms_message[/\d{12}\z/]
        fill_in 'SMS Code', :with=>sms_code
        click_button 'Confirm SMS Backup Number'
        page.find('#notice_flash').text.must_equal 'SMS authentication has been setup'
        page.html.must_include 'With 2nd Factor: totp'

        logout
        login

        page.html.must_match(/Authenticate Using WebAuthn.*Authenticate Using TOTP.*Authenticate Using SMS Code.*Authenticate Using Recovery Code/m)
        click_link 'Authenticate Using SMS Code'

        click_button 'Send SMS Code'
        sms_code = sms_message[/\d{6}\z/]
        fill_in 'SMS Code', :with=>sms_code
        click_button 'Authenticate via SMS Code'
        page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
        page.html.must_include 'With 2nd Factor: sms_code'

        visit '/multifactor-manage'
        page.html.must_match(/Setup Multifactor Authentication.*Setup WebAuthn Authentication.*View Authentication Recovery Codes.*Remove Multifactor Authentication.*Remove WebAuthn Authenticator.*Disable TOTP Authentication.*Disable SMS Authentication/m)
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
        page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
        page.html.must_include 'With 2nd Factor: recovery_code'

        require_password = true

        visit '/multifactor-manage'
        click_link 'Remove All Multifactor Authentication Methods'
        page.title.must_equal 'Remove All Multifactor Authentication Methods'
        click_button 'Remove All Multifactor Authentication Methods'
        page.find('#error_flash').text.must_equal 'Unable to remove all multifactor authentication methods'
        page.html.must_include 'invalid password'

        fill_in 'Password', :with=>'0123456789'
        click_button 'Remove All Multifactor Authentication Methods'
        page.find('#notice_flash').text.must_equal 'All multifactor authentication methods have been disabled'
        page.html.must_include 'Without 2nd Factor'
        [:account_webauthn_user_ids, :account_webauthn_keys, :account_otp_keys, :account_recovery_codes, :account_sms_codes].each do |t|
          DB[t].count.must_equal 0
        end
      end
    end

    it "should remove 2FA session when removing all authentication methods" do
      sms_message = nil
      rodauth do
        enable :login, :logout, :otp, :sms_codes, :recovery_codes, :webauthn
        hmac_secret '123'
        two_factor_modifications_require_password? false
        sms_send { |phone, msg| sms_message = msg }
        recovery_codes_primary? true
        sms_codes_primary? true
      end
      first_request = nil
      roda do |r|
        first_request ||= r
        r.rodauth
        rodauth.require_authentication
        view :content=>"2FA authenticated: #{rodauth.two_factor_authenticated?}"
      end

      login
      webauthn_client = WebAuthn::FakeClient.new(first_request.base_url)

      visit '/otp-setup'
      secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
      totp = ROTP::TOTP.new(secret)
      fill_in 'Authentication Code', :with=>totp.now
      click_button 'Setup TOTP Authentication'
      page.find('#notice_flash').text.must_equal 'TOTP authentication is now setup'

      visit '/multifactor-disable'
      click_button 'Remove All Multifactor Authentication Methods'
      page.find('#notice_flash').text.must_equal 'All multifactor authentication methods have been disabled'
      page.html.must_include '2FA authenticated: false'

      visit '/recovery-codes'
      click_on 'View Authentication Recovery Codes'
      click_on 'Add Authentication Recovery Codes'
      page.find('#notice_flash').text.must_equal 'Additional authentication recovery codes have been added'
      recovery_code = find('#recovery-codes').text.split.first
      logout
      login
      fill_in 'Recovery Code', :with=>recovery_code
      click_button 'Authenticate via Recovery Code'
      page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'

      visit '/multifactor-disable'
      click_button 'Remove All Multifactor Authentication Methods'
      page.find('#notice_flash').text.must_equal 'All multifactor authentication methods have been disabled'
      page.html.must_include '2FA authenticated: false'

      visit '/sms-setup'
      fill_in 'Phone Number', :with=>'(123) 456-7890'
      click_button 'Setup SMS Backup Number'
      page.find('#notice_flash').text.must_equal 'SMS authentication needs confirmation'
      sms_code = sms_message[/\d{12}\z/]
      fill_in 'SMS Code', :with=>sms_code
      click_button 'Confirm SMS Backup Number'
      page.find('#notice_flash').text.must_equal 'SMS authentication has been setup'

      visit '/multifactor-disable'
      click_button 'Remove All Multifactor Authentication Methods'
      page.find('#notice_flash').text.must_equal 'All multifactor authentication methods have been disabled'
      page.html.must_include '2FA authenticated: false'

      visit '/webauthn-setup'
      challenge = JSON.parse(page.find('#webauthn-setup-form')['data-credential-options'])['challenge']
      fill_in 'webauthn_setup', :with=>webauthn_client.create(challenge: challenge).to_json
      click_button 'Setup WebAuthn Authentication'
      page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'

      visit '/multifactor-disable'
      click_button 'Remove All Multifactor Authentication Methods'
      page.find('#notice_flash').text.must_equal 'All multifactor authentication methods have been disabled'
      page.html.must_include '2FA authenticated: false'
    end
  end
end
