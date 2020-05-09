require_relative 'spec_helper'

describe 'Rodauth verify_account_grace_period feature' do
  it "should support grace periods when verifying accounts" do
    rodauth do
      enable :login, :logout, :change_password, :create_account, :verify_account_grace_period
      change_password_requires_password? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In#{rodauth.verified_account?}" : "Not Logged"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    link = email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')
    page.body.must_include('Logged Infalse')
    page.current_path.must_equal '/'

    logout
    login(:login=>'foo@example2.com')
    page.body.must_include('Logged Infalse')

    visit '/change-password'
    fill_in 'New Password', :with=>'012345678'
    fill_in 'Confirm Password', :with=>'012345678'
    click_button 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"

    DB[:account_verification_keys].update(:requested_at=>Time.now - 100000)

    logout
    login(:login=>'foo@example2.com', :pass=>'012345678')
    page.find('#error_flash').text.must_equal 'The account you tried to login with is currently awaiting verification'
    visit '/'
    page.body.must_include('Not Logged')

    visit link
    click_button 'Verify Account'
    page.find('#notice_flash').text.must_equal "Your account has been verified"
    page.body.must_include('Logged Intrue')
  end

  it "should resend verify account email if attempting to create new account with same login" do
    rodauth do
      enable :login, :logout, :change_password, :create_account, :verify_account_grace_period
      change_password_requires_password? false
      verify_account_email_last_sent_column nil
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In#{rodauth.verified_account?}" : "Not Logged"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    link = email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')
    page.body.must_include('Logged Infalse')
    page.current_path.must_equal '/'

    logout
    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Create Account'
    click_button 'Send Verification Email Again'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    page.current_path.must_equal '/'
    email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com').must_equal link

    visit link
    click_button 'Verify Account'
    page.find('#notice_flash').text.must_equal "Your account has been verified"
    page.body.must_include('Logged Intrue')
  end

  it "should not allow changing logins for unverified accounts" do
    rodauth do
      enable :login, :logout, :change_login, :verify_account_grace_period
      change_login_requires_password? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In#{rodauth.verified_account?}" : "Not Logged"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Create Account'
    link = email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')

    visit '/change-login'
    page.find('#error_flash').text.must_equal "Please verify this account before changing the login"
    page.current_path.must_equal '/'

    visit link
    click_button 'Verify Account'
    page.find('#notice_flash').text.must_equal "Your account has been verified"
    page.body.must_include('Logged Intrue')

    visit '/change-login'
    fill_in 'Login', :with=>'foo3@example.com'
    click_button 'Change Login'
    page.find('#notice_flash').text.must_equal "Your login has been changed"
    page.current_path.must_equal '/'
  end

  it "should allow verifying accounts while logged in during grace period" do
    rodauth do
      enable :login, :verify_account_grace_period
      already_logged_in{request.redirect '/'}
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In#{rodauth.verified_account?}" : "Not Logged"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    link = email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')
    page.body.must_include('Logged Infalse')
    page.current_path.must_equal '/'

    visit link
    click_button 'Verify Account'
    page.find('#notice_flash').text.must_equal "Your account has been verified"
    page.body.must_include('Logged Intrue')
  end

  it "should not allow login when password was not set" do
    rodauth do
      enable :login, :logout, :verify_account_grace_period
      verify_account_set_password? true
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In#{rodauth.verified_account?}" : "Not Logged"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Create Account'
    link = email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')

    logout
    visit '/login'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Login'
    page.find('#error_flash').text.must_equal "The account you tried to login with is currently awaiting verification"
  end

  it "should remove verify keys if closing unverified accounts" do
    rodauth do
      enable :login, :close_account, :verify_account_grace_period
      already_logged_in{request.redirect '/'}
      close_account_requires_password? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In#{rodauth.verified_account?}" : "Not Logged"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Create Account'
    email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')

    visit '/close-account'
    click_button 'Close Account'
    page.find('#notice_flash').text.must_equal "Your account has been closed"
    DB[:account_verification_keys].must_be :empty?
  end

  it "should not support email authentication for unverified accounts in grace period if email_auth enabled after" do
    rodauth do
      enable :login, :logout, :change_password, :create_account, :verify_account_grace_period, :email_auth
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In#{rodauth.verified_account?}" : "Not Logged"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')
    page.body.must_include('Logged Infalse')
    page.current_path.must_equal '/'

    logout

    visit '/login'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Login'
    page.body.wont_include('Send Login Link Via Email')
  end

  it "should not support email authentication for unverified accounts in grace period if email_auth enabled before" do
    rodauth do
      enable :login, :logout, :change_password, :create_account, :email_auth, :verify_account_grace_period
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In#{rodauth.verified_account?}" : "Not Logged"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')
    page.body.must_include('Logged Infalse')
    page.current_path.must_equal '/'

    logout

    visit '/login'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Login'
    page.body.wont_include('Send Login Link Via Email')
  end
end
