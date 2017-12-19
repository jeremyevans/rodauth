require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth account expiration feature' do
  it "should force account expiration after x number of days since last login" do
    rodauth do
      enable :login, :logout, :account_expiration
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In#{rodauth.last_account_login_at.strftime('%m%d%y')}" : "Not Logged"}
    end

    now = Time.now
    2.times do
      login
      page.body.must_include "Logged In#{now.strftime('%m%d%y')}"

      logout
    end

    DB[:account_activity_times].update(:last_login_at => Time.now - 181*86400)

    2.times do
      login
      page.body.must_include 'Not Logged'
      page.find('#error_flash').text.must_equal "You cannot log into this account as it has expired"
    end
  end

  it "should not allow resetting of passwords for expired accounts" do
    rodauth do
      enable :login, :logout, :account_expiration, :reset_password
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In#{rodauth.last_account_login_at.strftime('%m%d%y')}" : "Not Logged"}
    end

    now = Time.now
    login
    page.body.must_include "Logged In#{now.strftime('%m%d%y')}"
    logout

    visit '/login'
    click_link 'Forgot Password?'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Request Password Reset'
    link = email_link(/(\/reset-password\?key=.+)$/)

    visit link
    fill_in 'Password', :with=>'0123456'
    fill_in 'Confirm Password', :with=>'0123456'
    click_button 'Reset Password'
    page.find('#notice_flash').text.must_equal "Your password has been reset"
    page.current_path.must_equal '/'

    visit '/login'
    click_link 'Forgot Password?'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Request Password Reset'
    link = email_link(/(\/reset-password\?key=.+)$/)

    DB[:account_activity_times].update(:last_login_at => Time.now - 181*86400)

    visit link
    page.title.must_equal 'Reset Password'
    fill_in 'Password', :with=>'01234567'
    fill_in 'Confirm Password', :with=>'01234567'
    click_button 'Reset Password'
    page.find('#error_flash').text.must_equal "You cannot log into this account as it has expired"
    page.body.must_include 'Not Logged'
    page.current_path.must_equal '/'

    visit '/login'
    click_link 'Forgot Password?'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Request Password Reset'
    page.find('#error_flash').text.must_equal "You cannot log into this account as it has expired"
    page.body.must_include 'Not Logged'
    page.current_path.must_equal '/'
  end

  it "should not allow account unlocks for expired accounts" do
    rodauth do
      enable :lockout, :account_expiration, :logout
      max_invalid_logins 2
      unlock_account_autologin? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>(rodauth.logged_in? ? "Logged In" : "Not Logged")}
    end

    login
    logout

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    3.times do
      fill_in 'Password', :with=>'012345678910'
      click_button 'Login'
    end

    page.body.must_include("This account is currently locked out")
    click_button 'Request Account Unlock'
    page.find('#notice_flash').text.must_equal 'An email has been sent to you with a link to unlock your account'
    link = email_link(/(\/unlock-account\?key=.+)$/)

    visit link
    click_button 'Unlock Account'
    page.find('#notice_flash').text.must_equal 'Your account has been unlocked'
    page.body.must_include('Not Logged')

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    3.times do
      fill_in 'Password', :with=>'012345678910'
      click_button 'Login'
    end

    page.body.must_include("This account is currently locked out")
    click_button 'Request Account Unlock'
    page.find('#notice_flash').text.must_equal 'An email has been sent to you with a link to unlock your account'
    link = email_link(/(\/unlock-account\?key=.+)$/)

    DB[:account_activity_times].update(:last_login_at => Time.now - 181*86400)

    visit link
    click_button 'Unlock Account'
    page.find('#error_flash').text.must_equal "You cannot log into this account as it has expired"
    page.body.must_include 'Not Logged'
    page.current_path.must_equal '/'
  end

  it "should not allow account unlock requests for expired accounts" do
    rodauth do
      enable :lockout, :account_expiration, :logout
      max_invalid_logins 2
      unlock_account_autologin? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>(rodauth.logged_in? ? "Logged In" : "Not Logged")}
    end

    login
    logout

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    3.times do
      fill_in 'Password', :with=>'012345678910'
      click_button 'Login'
    end

    DB[:account_activity_times].update(:last_login_at => Time.now - 181*86400)

    page.body.must_include("This account is currently locked out")
    click_button 'Request Account Unlock'
    page.find('#error_flash').text.must_equal "You cannot log into this account as it has expired"
    page.body.must_include 'Not Logged'
    page.current_path.must_equal '/'
  end

  it "should use last activity time if configured" do
    rodauth do
      enable :login, :logout, :account_expiration
      expire_account_on_last_activity? true
      account_expiration_error_flash{"Account expired on #{account_expired_at.strftime('%m%d%y')}"}
    end
    roda do |r|
      r.is("a"){view :content=>"Logged In#{rodauth.last_account_activity_at.strftime('%m%d%y')}"}
      rodauth.update_last_activity
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In#{rodauth.last_account_activity_at.strftime('%m%d%y')}" : 'Not Logged'}
    end

    now = Time.now
    login
    page.body.must_include "Logged In#{now.strftime('%m%d%y')}"

    DB[:account_activity_times].count.must_equal 1
    DB[:account_activity_times].delete

    visit '/'
    DB[:account_activity_times].count.must_equal 1

    t1 = now - 179*86400
    DB[:account_activity_times].update(:last_activity_at => t1)
    visit '/a'
    page.body.must_include "Logged In#{t1.strftime('%m%d%y')}"

    logout

    t2 = now - 181*86400
    DB[:account_activity_times].update(:last_activity_at => t2).must_equal 1

    login
    page.body.must_include 'Not Logged'
    page.find('#error_flash').text.must_equal "Account expired on #{now.strftime('%m%d%y')}"

    DB[:account_activity_times].update(:expired_at=>t1).must_equal 1

    login
    page.body.must_include 'Not Logged'
    page.find('#error_flash').text.must_equal "Account expired on #{t1.strftime('%m%d%y')}"
  end

  it "should remove account activity data when closing accounts" do
    rodauth do
      enable :login, :close_account, :account_expiration
      close_account_requires_password? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In#{rodauth.last_account_login_at.strftime('%m%d%y')}" : "Not Logged"}
    end

    login
    DB[:account_activity_times].count.must_equal 1
    visit '/close-account'
    click_button 'Close Account'
    DB[:account_activity_times].count.must_equal 0
  end
end
