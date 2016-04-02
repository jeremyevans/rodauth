require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth OTP feature' do
  it "should allow two factor authentication setup, login, recovery, removal" do
    sms_phone = sms_message = nil
    rodauth do
      enable :login, :logout, :otp, :otp_recovery_codes, :otp_sms_codes
      otp_sms_send do |phone, msg|
        proc{super(phone, msg)}.must_raise NotImplementedError
        sms_phone = phone
        sms_message = msg
      end
    end
    roda do |r|
      r.rodauth

      r.redirect '/login' unless rodauth.logged_in?

      if rodauth.has_otp?
        r.redirect '/otp' unless rodauth.authenticated?
        view :content=>"With OTP"
      else    
        view :content=>"Without OTP"
      end
    end

    login
    page.html.must_include('Without OTP')

    %w'/otp/disable /otp/recovery /otp/recovery-codes /otp/sms-setup /otp/sms-disable /otp/sms-confirm /otp/sms-request /otp/sms-auth /otp'.each do |path|
      visit path
      page.find('#notice_flash').text.must_equal 'This account has not been setup for two factor authentication'
      page.current_path.must_equal '/otp/setup'
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
    page.current_path.must_equal '/otp'

    %w'/otp/disable /otp/recovery-codes /otp/setup /otp/sms-setup /otp/sms-disable /otp/sms-confirm'.each do |path|
      visit path
      page.find('#notice_flash').text.must_equal 'You need to authenticate via 2nd factor before continuing.'
      page.current_path.must_equal '/otp'
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

    visit '/otp/setup'
    page.find('#notice_flash').text.must_equal 'You have already setup two factor authentication'

    %w'/otp /otp/recovery /otp/sms-request /otp/sms-auth'.each do |path|
      visit path
      page.find('#notice_flash').text.must_equal 'Already authenticated via 2nd factor'
    end

    visit '/otp/sms-disable'
    page.find('#notice_flash').text.must_equal 'SMS authentication has not been setup yet.'

    visit '/otp/sms-setup'
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
    sms_message.must_match(/\ASMS confirmation code for www\.example\.com is \d+\z/)

    page.title.must_equal 'Confirm SMS Backup Number'
    fill_in 'SMS Code', :with=>"asdf"
    click_button 'Confirm SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Invalid or out of date SMS confirmation code used, must setup SMS authentication again.'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'

    visit '/otp/sms-setup'
    page.find('#notice_flash').text.must_equal 'SMS authentication needs confirmation.'
    page.title.must_equal 'Confirm SMS Backup Number'

    DB[:account_otp_sms_codes].update(:code_issued_at=>Time.now - 310)
    sms_code = sms_message[/\d+\z/]
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'
    page.find('#error_flash').text.must_equal 'Invalid or out of date SMS confirmation code used, must setup SMS authentication again.'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'
    sms_code = sms_message[/\d+\z/]
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'
    page.find('#notice_flash').text.must_equal 'SMS authentication has been setup.'

    %w'/otp/sms-setup /otp/sms-confirm'.each do |path|
      visit path
      page.find('#notice_flash').text.must_equal 'SMS authentication has already been setup.'
      page.current_path.must_equal '/'
    end

    logout
    login

    visit '/otp/sms-auth'
    page.current_path.must_equal '/otp/sms-request'
    page.find('#error_flash').text.must_equal 'No current SMS code for this account'

    sms_phone = sms_message = nil
    page.title.must_equal 'Send SMS Code'
    click_button 'Send SMS Code'
    sms_phone.must_equal '1234567890'
    sms_message.must_match(/\ASMS authentication code for www\.example\.com is \d+\z/)
    sms_code = sms_message[/\d+\z/]

    fill_in 'SMS Code', :with=>"asdf"
    click_button 'Authenticate via SMS Code'
    page.html.must_include 'invalid SMS code'
    page.find('#error_flash').text.must_equal 'Error authenticating via SMS code.'

    DB[:account_otp_sms_codes].update(:code_issued_at=>Time.now - 310)
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Authenticate via SMS Code'
    page.find('#error_flash').text.must_equal 'No current SMS code for this account'

    click_button 'Send SMS Code'
    sms_code = sms_message[/\d+\z/]
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Authenticate via SMS Code'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'

    logout
    login

    visit '/otp/sms-request'
    click_button 'Send SMS Code'

    5.times do
      click_button 'Authenticate via SMS Code'
      page.find('#error_flash').text.must_equal 'Error authenticating via SMS code.'
      page.current_path.must_equal '/otp/sms-auth'
    end

    click_button 'Authenticate via SMS Code'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out.'
    page.current_path.must_equal '/otp'

    visit '/otp/sms-request'
    page.find('#error_flash').text.must_equal 'SMS authentication has been locked out.'
    page.current_path.must_equal '/otp'

    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate via 2nd Factor'

    visit '/otp/sms-disable'
    page.title.must_equal 'Disable Backup SMS Authentication'
    fill_in 'Password', :with=>'012345678'
    click_button 'Disable Backup SMS Authentication'
    page.find('#error_flash').text.must_equal 'Error disabling SMS authentication'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'Disable Backup SMS Authentication'
    page.find('#notice_flash').text.must_equal 'SMS authentication has been disabled.'
    page.current_path.must_equal '/'

    visit '/otp/sms-setup'
    page.title.must_equal 'Setup SMS Backup Number'
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'
    sms_code = sms_message[/\d+\z/]
    fill_in 'SMS Code', :with=>sms_code
    click_button 'Confirm SMS Backup Number'

    visit '/otp/recovery-codes'
    page.title.must_equal 'View Authentication Recovery Codes'
    fill_in 'Password', :with=>'012345678'
    click_button 'View Authentication Recovery Codes'
    page.find('#error_flash').text.must_equal 'Unable to view recovery codes.'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'View Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    recovery_codes = find('#otp-recovery-codes').text.split
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

    visit '/otp/recovery-codes'
    fill_in 'Password', :with=>'0123456789'
    click_button 'View Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    page.html.wont_include(recovery_code)
    find('#otp-recovery-codes').text.split.length.must_equal 15

    click_button 'Add Authentication Recovery Codes'
    page.find('#error_flash').text.must_equal 'Unable to add recovery codes.'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'View Authentication Recovery Codes'
    find('#otp-recovery-codes').text.split.length.must_equal 15
    fill_in 'Password', :with=>'0123456789'
    click_button 'Add Authentication Recovery Codes'
    page.find('#notice_flash').text.must_equal 'Additional authentication recovery codes have been added.'
    find('#otp-recovery-codes').text.split.length.must_equal 16
    page.html.wont_include('Add Additional Authentication Recovery Codes')

    visit '/otp/disable'
    fill_in 'Password', :with=>'012345678'
    click_button 'Disable Two Factor Authentication'
    page.find('#error_flash').text.must_equal 'Error disabling up two factor authentication'
    page.html.must_include 'invalid password'

    fill_in 'Password', :with=>'0123456789'
    click_button 'Disable Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication has been disabled'
    page.html.must_include 'Without OTP'
    [:account_otp_keys, :account_otp_recovery_codes, :account_otp_sms_codes].each do |t|
      DB[t].count.must_equal 0
    end
  end

  it "should allow namespaced two factor authentication without password requirements" do
    rodauth do
      enable :login, :logout, :otp_recovery_codes
      otp_modifications_require_password? false
      prefix "/auth"
    end
    roda do |r|
      r.on "auth" do
        r.rodauth
      end

      r.redirect '/auth/login' unless rodauth.logged_in?

      if rodauth.has_otp?
        r.redirect '/auth/otp' unless rodauth.otp_authenticated?
        view :content=>"With OTP"
      else    
        view :content=>"Without OTP"
      end
    end

    login
    page.html.must_include('Without OTP')

    visit '/auth/otp/disable'
    page.find('#notice_flash').text.must_equal 'This account has not been setup for two factor authentication'
    page.current_path.must_equal '/auth/otp/setup'

    visit '/auth/otp/recovery'
    page.find('#notice_flash').text.must_equal 'This account has not been setup for two factor authentication'
    page.current_path.must_equal '/auth/otp/setup'

    visit '/auth/otp/recovery-codes'
    page.find('#notice_flash').text.must_equal 'This account has not been setup for two factor authentication'
    page.current_path.must_equal '/auth/otp/setup'

    visit '/auth/otp'
    page.find('#notice_flash').text.must_equal 'This account has not been setup for two factor authentication'
    page.current_path.must_equal '/auth/otp/setup'

    page.title.must_equal 'Setup Two Factor Authentication'
    page.html.must_include '<svg' 
    secret = page.html.match(/Secret: ([a-z2-7]{16})/)[1]
    totp = ROTP::TOTP.new(secret)
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

    page.current_path.must_equal '/auth/otp'

    visit '/auth/otp/disable'
    page.find('#notice_flash').text.must_equal 'You need to authenticate via 2nd factor before continuing.'
    page.current_path.must_equal '/auth/otp'

    visit '/auth/otp/recovery-codes'
    page.find('#notice_flash').text.must_equal 'You need to authenticate via 2nd factor before continuing.'
    page.current_path.must_equal '/auth/otp'

    visit '/auth/otp/setup'
    page.find('#notice_flash').text.must_equal 'You need to authenticate via 2nd factor before continuing.'
    page.current_path.must_equal '/auth/otp'

    page.title.must_equal 'Enter Authentication Code'
    fill_in 'Authentication Code', :with=>"asdf"
    click_button 'Authenticate via 2nd Factor'
    page.find('#error_flash').text.must_equal 'Error logging in via two factor authentication'
    page.html.must_include 'Invalid authentication code'

    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate via 2nd Factor'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
    page.html.must_include 'With OTP'

    visit '/auth/otp'
    page.find('#notice_flash').text.must_equal 'Already authenticated via 2nd factor'

    visit '/auth/otp/setup'
    page.find('#notice_flash').text.must_equal 'You have already setup two factor authentication'

    visit '/auth/otp/recovery'
    page.find('#notice_flash').text.must_equal 'Already authenticated via 2nd factor'

    visit '/auth/otp/recovery-codes'
    page.title.must_equal 'View Authentication Recovery Codes'
    click_button 'View Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    recovery_codes = find('#otp-recovery-codes').text.split
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

    visit '/auth/otp/recovery-codes'
    click_button 'View Authentication Recovery Codes'
    page.title.must_equal 'Authentication Recovery Codes'
    page.html.wont_include(recovery_code)
    find('#otp-recovery-codes').text.split.length.must_equal 15
    click_button 'Add Authentication Recovery Codes'
    page.find('#notice_flash').text.must_equal 'Additional authentication recovery codes have been added.'
    find('#otp-recovery-codes').text.split.length.must_equal 16
    page.html.wont_include('Add Additional Authentication Recovery Codes')

    visit '/auth/otp/disable'
    click_button 'Disable Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication has been disabled'
    page.html.must_include 'Without OTP'
    [:account_otp_keys, :account_otp_recovery_codes].each do |t|
      DB[t].count.must_equal 0
    end
  end

  it "should require login and OTP authentication to perform certain actions if user signed up for OTP" do
    rodauth do
      enable :login, :logout, :change_password, :change_login, :close_account, :otp_recovery_codes
    end
    roda do |r|
      r.rodauth

      r.is "a" do
        rodauth.require_authentication
        view(:content=>"a")
      end

      view(:content=>"b")
    end

    visit '/change-password'
    page.current_path.must_equal '/login'

    visit '/change-login'
    page.current_path.must_equal '/login'

    visit '/close-account'
    page.current_path.must_equal '/login'

    visit '/a'
    page.current_path.must_equal '/login'

    login

    visit '/change-password'
    page.current_path.must_equal '/change-password'

    visit '/change-login'
    page.current_path.must_equal '/change-login'

    visit '/close-account'
    page.current_path.must_equal '/close-account'

    visit '/a'
    page.current_path.must_equal '/a'

    visit '/otp/setup'
    secret = page.html.match(/Secret: ([a-z2-7]{16})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'
    page.current_path.must_equal '/'

    logout
    login

    visit '/change-password'
    page.current_path.must_equal '/otp'

    visit '/change-login'
    page.current_path.must_equal '/otp'

    visit '/close-account'
    page.current_path.must_equal '/otp'

    visit '/a'
    page.current_path.must_equal '/otp'
  end

  it "should handle attempts to insert a duplicate recovery code" do
    keys = ['a', 'a', 'b']
    rodauth do
      enable :login, :logout, :otp_recovery_codes
      otp_recovery_codes_limit 2
      otp_new_recovery_code{keys.shift}
    end
    roda do |r|
      r.rodauth

      r.redirect '/login' unless rodauth.logged_in?

      if rodauth.has_otp?
        r.redirect '/otp' unless rodauth.authenticated?
        view :content=>"With OTP"
      else    
        view :content=>"Without OTP"
      end
    end

    login
    page.html.must_include('Without OTP')

    visit '/otp'
    secret = page.html.match(/Secret: ([a-z2-7]{16})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication is now setup'
    page.current_path.must_equal '/'
    DB[:account_otp_recovery_codes].select_order_map(:code).must_equal ['a', 'b']
  end

  it "should allow two factor authentication setup, login, removal without recovery" do
    rodauth{enable :login, :logout, :otp}
    roda do |r|
      r.rodauth

      r.redirect '/login' unless rodauth.logged_in?

      if rodauth.has_otp?
        r.redirect '/otp' unless rodauth.authenticated?
        view :content=>"With OTP"
      else    
        view :content=>"Without OTP"
      end
    end

    visit '/otp/recovery'
    page.current_path.must_equal '/login'
    visit '/otp/recovery-codes'
    page.current_path.must_equal '/login'

    login
    page.html.must_include('Without OTP')

    visit '/otp/setup'
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

    visit '/otp'
    page.title.must_equal 'Enter Authentication Code'
    page.html.wont_include 'Authenticate using recovery code'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate via 2nd Factor'
    page.find('#notice_flash').text.must_equal 'You have been authenticated via 2nd factor'
    page.html.must_include 'With OTP'

    visit '/otp/disable'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Disable Two Factor Authentication'
    page.find('#notice_flash').text.must_equal 'Two factor authentication has been disabled'
    page.html.must_include 'Without OTP'
    DB[:account_otp_keys].count.must_equal 0
  end

  it "should remove otp data when closing accounts" do
    rodauth do
      enable :login, :logout, :otp_recovery_codes, :otp_sms_codes, :close_account
      otp_modifications_require_password? false
      close_account_requires_password? false
      otp_sms_send{|*|}
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>"With OTP"}
    end

    login

    visit '/otp/setup'
    secret = page.html.match(/Secret: ([a-z2-7]{16})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup Two Factor Authentication'

    visit '/otp/sms-setup'
    fill_in 'Phone Number', :with=>'(123) 456-7890'
    click_button 'Setup SMS Backup Number'

    DB[:account_otp_keys].count.must_equal 1
    DB[:account_otp_recovery_codes].count.must_equal 16
    DB[:account_otp_sms_codes].count.must_equal 1
    visit '/close-account'
    click_button 'Close Account'
    [:account_otp_keys, :account_otp_recovery_codes, :account_otp_sms_codes].each do |t|
      DB[t].count.must_equal 0
    end
  end
end
