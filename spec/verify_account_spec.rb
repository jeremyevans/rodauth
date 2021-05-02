require_relative 'spec_helper'

describe 'Rodauth verify_account feature' do
  it "should support verifying accounts" do
    last_sent_column = nil
    secret = nil
    allow_raw_token = false
    rodauth do
      enable :login, :create_account, :verify_account
      verify_account_autologin? false
      verify_account_email_last_sent_column{last_sent_column}
      hmac_secret{secret}
      allow_raw_email_token?{allow_raw_token}
      verify_account_set_password? false
      require_login_confirmation? true
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Confirm Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    page.current_path.must_equal '/'

    link = email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')
    login(:login=>'foo@example2.com')
    page.find('#error_flash').text.must_equal 'The account you tried to login with is currently awaiting verification'
    page.html.must_include("If you no longer have the email to verify the account, you can request that it be resent to you")
    click_button 'Send Verification Email Again'
    page.current_path.must_equal '/'
    email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com').must_equal link

    visit '/login'
    click_link 'Resend Verify Account Information'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Send Verification Email Again'
    page.current_path.must_equal '/'
    email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com').must_equal link

    visit '/login'
    last_sent_column = :email_last_sent
    click_link 'Resend Verify Account Information'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Send Verification Email Again'
    page.current_path.must_equal '/'
    page.find('#error_flash').text.must_equal "An email has recently been sent to you with a link to verify your account"
    Mail::TestMailer.deliveries.must_equal []

    visit '/login'
    DB[:account_verification_keys].update(:email_last_sent => Time.now - 250).must_equal 1
    click_link 'Resend Verify Account Information'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Send Verification Email Again'
    page.current_path.must_equal '/'
    page.find('#error_flash').text.must_equal "An email has recently been sent to you with a link to verify your account"
    Mail::TestMailer.deliveries.must_equal []

    visit '/login'
    DB[:account_verification_keys].update(:email_last_sent => Time.now - 350).must_equal 1
    click_link 'Resend Verify Account Information'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Send Verification Email Again'
    page.current_path.must_equal '/'
    email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com').must_equal link

    DB[:account_verification_keys].update(:email_last_sent => Time.now - 350).must_equal 1
    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Create Account'
    click_button 'Send Verification Email Again'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    page.current_path.must_equal '/'

    link = email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')
    visit link[0...-1]
    page.find('#error_flash').text.must_equal "There was an error verifying your account: invalid verify account key"

    secret = SecureRandom.random_bytes(32)
    visit link
    page.find('#error_flash').text.must_equal "There was an error verifying your account: invalid verify account key"

    allow_raw_token = true
    visit link
    click_button 'Verify Account'
    page.find('#notice_flash').text.must_equal "Your account has been verified"
    page.current_path.must_equal '/'

    login(:login=>'foo@example2.com')
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.current_path.must_equal '/'
  end

  [false, true].each do |ph|
    it "should support setting passwords when verifying accounts #{'with account_password_hash_column' if ph}" do
      initial_secret = secret = SecureRandom.random_bytes(32)
      rodauth do
        enable :login, :create_account, :verify_account
        account_password_hash_column :ph if ph
        verify_account_autologin? false
        hmac_secret{secret}
      end
      roda do |r|
        r.rodauth
        r.root{view :content=>""}
      end

      visit '/create-account'
      fill_in 'Login', :with=>'foo@example2.com'
      click_button 'Create Account'
      page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"

      link = email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')

      secret = SecureRandom.random_bytes(32)
      visit link
      page.find('#error_flash').text.must_equal "There was an error verifying your account: invalid verify account key"

      secret = initial_secret
      visit link
      page.find_by_id('password')[:autocomplete].must_equal 'new-password'
      fill_in 'Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'012345678'
      click_button 'Verify Account'
      page.html.must_include("passwords do not match")
      page.find('#error_flash').text.must_equal "Unable to verify account"

      fill_in 'Password', :with=>'0123'
      fill_in 'Confirm Password', :with=>'0123'
      click_button 'Verify Account'
      page.html.must_include("invalid password, does not meet requirements (minimum 6 characters)")
      page.find('#error_flash').text.must_equal "Unable to verify account"

      fill_in 'Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'0123456789'
      click_button 'Verify Account'
      page.find('#notice_flash').text.must_equal "Your account has been verified"
      page.current_path.must_equal '/'

      login(:login=>'foo@example2.com', :password=>'0123456789')
      page.find('#notice_flash').text.must_equal 'You have been logged in'
      page.current_path.must_equal '/'
    end
  end

  it "should indicate when resending verification email does not occur due to missing key" do
    rodauth do
      enable :login, :verify_account
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    page.current_path.must_equal '/'

    email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')
    login(:login=>'foo@example2.com')
    page.find('#error_flash').text.must_equal 'The account you tried to login with is currently awaiting verification'
    DB[:account_verification_keys].delete
    click_button 'Send Verification Email Again'
    page.find('#error_flash').text.must_equal 'Unable to resend verify account email'

    proc{visit '/verify-account'}.must_raise RuntimeError
  end

  it "should support autologin when verifying accounts" do
    rodauth do
      enable :login, :create_account, :verify_account
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    page.current_path.must_equal '/'

    link = email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')
    visit link
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Verify Account'
    page.find('#notice_flash').text.must_equal "Your account has been verified"
    page.body.must_include 'Logged In'
  end

  it "should handle uniqueness errors raised when inserting verify account token" do
    rodauth do
      enable :login, :verify_account
    end
    roda do |r|
      def rodauth.raised_uniqueness_violation(*) super; true; end
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    page.current_path.must_equal '/'

    link = email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')
    visit link
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Verify Account'
    page.find('#notice_flash').text.must_equal "Your account has been verified"
    page.body.must_include 'Logged In'
  end

  it "should handle uniqueness errors raised when inserting verify account token, if there isn't a matching key, by reraising" do
    rodauth do
      enable :login, :verify_account
    end
    roda do |r|
      def rodauth.raised_uniqueness_violation(*) StandardError.new; end
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    proc{click_button 'Create Account'}.must_raise StandardError
  end

  it "should not attempt to insert a verify account key if one already exists" do
    rodauth do
      enable :login, :verify_account
      create_verify_account_key do
        super()
        def self.raised_uniqueness_violation(*) raise ArgumentError; end
        super()
      end
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    page.current_path.must_equal '/'

    link = email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')
    visit link
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Verify Account'
    page.find('#notice_flash').text.must_equal "Your account has been verified"
    page.body.must_include 'Logged In'
  end

  [:jwt, :json].each do |json|
    it "should support verifying accounts via #{json}" do
      rodauth do
        enable :login, :create_account, :verify_account
        verify_account_autologin? false
        verify_account_email_body{verify_account_email_link}
        verify_account_set_password? false
        verify_account_email_last_sent_column nil
      end
      roda(json) do |r|
        r.rodauth
        r.root{view :content=>""}
      end

      res = json_request('/create-account', :login=>'foo@example2.com', :password=>'0123456789', "password-confirm"=>'0123456789')
      res.must_equal [200, {'success'=>"An email has been sent to you with a link to verify your account"}]
      link = email_link(/key=.+$/, 'foo@example2.com')
      
      res = json_request('/create-account', :login=>'foo@example2.com', :password=>'0123456789', "password-confirm"=>'0123456789')
      res.must_equal [403, {"reason"=>"already_an_unopen_account_with_this_login", "error"=>"The account you tried to create is currently awaiting verification"}]

      res = json_request('/verify-account-resend', :login=>'foo@example.com')
      res.must_equal [401, {'reason'=> "no_matching_login", 'error'=>"Unable to resend verify account email"}]

      res = json_request('/verify-account-resend', :login=>'foo@example3.com')
      res.must_equal [401, {'reason'=> "no_matching_login", 'error'=>"Unable to resend verify account email"}]

      res = json_request('/login', :login=>'foo@example2.com',:password=>'0123456789')
      res.must_equal [403, {'reason'=> "unverified_account", 'error'=>"The account you tried to login with is currently awaiting verification"}]

      res = json_request('/verify-account-resend', :login=>'foo@example2.com')
      res.must_equal [200, {'success'=>"An email has been sent to you with a link to verify your account"}]
      email_link(/key=.+$/, 'foo@example2.com').must_equal link

      res = json_request('/verify-account')
      res.must_equal [401, {'reason'=> "invalid_verify_account_key", 'error'=>"Unable to verify account"}]

      res = json_request('/verify-account', :key=>link[4...-1])
      res.must_equal [401, {'reason'=> "invalid_verify_account_key", "error"=>"Unable to verify account"}]

      res = json_request('/verify-account', :key=>link[4..-1])
      res.must_equal [200, {"success"=>"Your account has been verified"}]

      json_login(:login=>'foo@example2.com')
    end
  end
end
