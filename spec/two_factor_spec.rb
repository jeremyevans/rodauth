require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth OTP feature' do
  it "should allow two factor authentication setup, login, recovery, removal" do
    sms_phone = sms_message = nil
    rodauth do
      enable :login, :logout, :otp, :recovery_codes, :sms_codes
      sms_send do |phone, msg|
        proc{super(phone, msg)}.must_raise NotImplementedError
        sms_phone = phone
        sms_message = msg
      end
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

    %w'/otp-disable /recovery-auth /recovery-codes /sms-setup /sms-disable /sms-confirm /sms-request /sms-auth /otp-auth'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'This account has not been setup for two factor authentication'
      page.current_path.must_equal '/otp-setup'
    end

    page.title.must_equal 'Setup Two Factor Authentication'
    page.html.must_include '<svg' 
    secret = page.html.match(/Secret: ([a-z2-7]{16})/)[1]
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

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'With OTP'

    logout
    login
    page.current_path.must_equal '/otp-auth'

    %w'/otp-disable /recovery-codes /otp-setup /sms-setup /sms-disable /sms-confirm'.each do |path|
      visit path
      page.find('#error_flash').text.must_equal 'You need to authenticate via 2nd factor before continuing.'
      page.current_path.must_equal '/otp-auth'
    end

    page.title.must_equal 'Enter Authentication Code'
    fill_in 'Authentication Code', :with=>"asdf"
    click_button 'Authenticate via 2nd Factor'
    page.find('#error_flash').text.must_equal 'Error logging in via two factor authentication'
    page.html.must_include 'Invalid authentication code'

    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate via 2nd Factor'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
    page.html.must_include 'With OTP'

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
    page.find('#error_flash').text.must_equal 'SMS authentication needs confirmation.'
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
    page.current_path.must_equal '/otp-auth'

    visit '/sms-request'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out.'
    page.current_path.must_equal '/otp-auth'

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
    page.find('#error_flash').text.must_equal 'Authentication code use locked out due to numerous failures. Can use recovery code to unlock. Can use SMS code to unlock.'

    click_button 'Send SMS Code'

    5.times do
      click_button 'Authenticate via SMS Code'
      page.find('#error_flash').text.must_equal 'Error authenticating via SMS code.'
    end

    click_button 'Authenticate via SMS Code'
    page.find('#error_flash').text.must_equal 'Authentication code use locked out due to numerous failures. Can use recovery code to unlock.'

    page.title.must_equal 'Enter Authentication Recovery Code'
    fill_in 'Recovery Code', :with=>"asdf"
    click_button 'Authenticate via Recovery Code'
    page.find('#error_flash').text.must_equal 'Error logging in via recovery code.'
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
    page.html.must_include 'Without OTP'
    [:account_otp_keys, :account_recovery_codes, :account_sms_codes].each do |t|
      DB[t].count.must_equal 0
    end
  end

  it "should allow namespaced two factor authentication without password requirements" do
    rodauth do
      enable :login, :logout, :otp, :recovery_codes
      two_factor_modifications_require_password? false
      otp_digits 8
      otp_interval 300
      prefix "/auth"
    end
    roda do |r|
      r.on "auth" do
        r.rodauth
      end

      r.redirect '/auth/login' unless rodauth.logged_in?

      if rodauth.two_factor_authentication_setup?
        r.redirect '/auth/otp-auth' unless rodauth.two_factor_authenticated?
        view :content=>"With OTP"
      else    
        view :content=>"Without OTP"
      end
    end

    login
    page.html.must_include('Without OTP')

    %w'/auth/otp-disable /auth/recovery-auth /auth/recovery-codes /auth/otp-auth'.each do
      visit '/auth/otp-disable'
      page.find('#error_flash').text.must_equal 'This account has not been setup for two factor authentication'
      page.current_path.must_equal '/auth/otp-setup'
    end

    page.title.must_equal 'Setup Two Factor Authentication'
    page.html.must_include '<svg' 
    secret = page.html.match(/Secret: ([a-z2-7]{16})/)[1]
    totp = ROTP::TOTP.new(secret, :digits=>8, :interval=>300)
    fill_in 'Authentication Code', :with=>"asdf"
    click_button 'Setup Two Factor Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up two factor authentication'
    page.html.must_include 'Invalid authentication code'

    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'With OTP'

    visit '/auth/logout'
    click_button 'Logout'
    login(:visit=>false)

    page.current_path.must_equal '/auth/otp-auth'

    visit '/auth/otp-disable'
    page.find('#error_flash').text.must_equal 'You need to authenticate via 2nd factor before continuing.'
    page.current_path.must_equal '/auth/otp-auth'

    visit '/auth/recovery-codes'
    page.find('#error_flash').text.must_equal 'You need to authenticate via 2nd factor before continuing.'
    page.current_path.must_equal '/auth/otp-auth'

    visit '/auth/otp-setup'
    page.find('#error_flash').text.must_equal 'You need to authenticate via 2nd factor before continuing.'
    page.current_path.must_equal '/auth/otp-auth'

    page.title.must_equal 'Enter Authentication Code'
    fill_in 'Authentication Code', :with=>"asdf"
    click_button 'Authenticate via 2nd Factor'
    page.find('#error_flash').text.must_equal 'Error logging in via two factor authentication'
    page.html.must_include 'Invalid authentication code'

    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate via 2nd Factor'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
    page.html.must_include 'With OTP'

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
    recovery_codes = find('#recovery-codes').text.split
    recovery_codes.length.must_equal 16
    recovery_code = recovery_codes.first

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

    page.find('#error_flash').text.must_equal 'Authentication code use locked out due to numerous failures. Can use recovery code to unlock.'
    page.title.must_equal 'Enter Authentication Recovery Code'
    fill_in 'Recovery Code', :with=>"asdf"
    click_button 'Authenticate via Recovery Code'
    page.find('#error_flash').text.must_equal 'Error logging in via recovery code.'
    page.html.must_include 'Invalid recovery code'
    fill_in 'Recovery Code', :with=>recovery_code
    click_button 'Authenticate via Recovery Code'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
    page.html.must_include 'With OTP'

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
    page.html.must_include 'Without OTP'
    [:account_otp_keys, :account_recovery_codes].each do |t|
      DB[t].count.must_equal 0
    end
  end

  it "should require login and OTP authentication to perform certain actions if user signed up for OTP" do
    rodauth do
      enable :login, :logout, :change_password, :change_login, :close_account, :otp, :recovery_codes
    end
    roda do |r|
      r.rodauth

      r.is "a" do
        rodauth.require_authentication
        view(:content=>"a")
      end

      view(:content=>"b")
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
    secret = page.html.match(/Secret: ([a-z2-7]{16})/)[1]
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
  end

  it "should handle attempts to insert a duplicate recovery code" do
    keys = ['a', 'a', 'b']
    rodauth do
      enable :login, :logout, :otp, :recovery_codes
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
    secret = page.html.match(/Secret: ([a-z2-7]{16})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication is now setup'
    page.current_path.must_equal '/'
    DB[:account_recovery_codes].select_order_map(:code).must_equal ['a', 'b']
  end

  it "should allow two factor authentication setup, login, removal without recovery" do
    rodauth{enable :login, :logout, :otp}
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
    secret = page.html.match(/Secret: ([a-z2-7]{16})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication is now setup'
    page.current_path.must_equal '/'
    page.html.must_include 'With OTP'

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
    secret = page.html.match(/Secret: ([a-z2-7]{16})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'

    visit '/sms-setup'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'

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
    page.find('#error_flash').text.must_equal 'SMS authentication needs confirmation.'
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
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'

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
    page.current_path.must_equal '/sms-request'

    %w'/recovery-codes /sms-setup /sms-disable /sms-confirm'.each do |path|
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
    page.find('#error_flash').text.must_equal 'Error logging in via recovery code.'
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

    [:account_recovery_codes, :account_sms_codes].each do |t|
      DB[t].count.must_equal 0
    end
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
    page.find('#error_flash').text.must_equal 'Error logging in via recovery code.'
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
    page.find('#error_flash').text.must_equal 'SMS authentication needs confirmation.'
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
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'

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
    page.body.must_include "With SMS Locked Out"
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out.'
    page.current_path.must_equal '/'

    visit '/sms-request'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out.'
    page.current_path.must_equal '/'

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
end
