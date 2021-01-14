require_relative 'spec_helper'

describe 'Rodauth verify_login_change feature' do
  it "should support verifying login changes" do
    rodauth do
      enable :login, :logout, :verify_login_change
      change_login_requires_password? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
    end

    login

    visit '/change-login'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Change Login'
    link = email_link(/(\/verify-login-change\?key=.+)$/, 'foo@example2.com')
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your login change"

    visit '/change-login'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Change Login'
    email_link(/(\/verify-login-change\?key=.+)$/, 'foo@example2.com').must_equal link

    visit '/change-login'
    fill_in 'Login', :with=>'foo@example3.com'
    click_button 'Change Login'
    new_link = email_link(/(\/verify-login-change\?key=.+)$/, 'foo@example3.com')
    new_link.wont_equal link

    logout

    proc{visit '/verify-login-change'}.must_raise RuntimeError

    visit link
    page.find('#error_flash').text.must_equal "There was an error verifying your login change: invalid verify login change key"

    visit new_link
    page.title.must_equal 'Verify Login Change'
    click_button 'Verify Login Change'
    page.find('#notice_flash').text.must_equal "Your login change has been verified"
    page.body.must_include('Not Logged')

    login
    page.find('#error_flash').text.must_equal "There was an error logging in"

    login(:login=>'foo@example3.com')
    page.body.must_include('Logged In')
  end

  it "should support verifying login changes with autologin" do
    rodauth do
      enable :login, :logout, :verify_login_change
      verify_login_change_autologin? true
      change_login_requires_password? false
      require_login_confirmation? true
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
    end

    login

    visit '/change-login'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Confirm Login', :with=>'foo@example2.com'
    click_button 'Change Login'
    link = email_link(/(\/verify-login-change\?key=.+)$/, 'foo@example2.com')

    visit link
    click_button 'Verify Login Change'
    page.find('#notice_flash').text.must_equal "Your login change has been verified"
    page.body.must_include('Logged In')
  end

  it "should check for duplicate accounts before sending verify email and before updating login" do
    rodauth do
      enable :login, :logout, :verify_login_change, :create_account
      change_login_requires_password? false
      create_account_autologin? false
      require_login_confirmation? true
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Confirm Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Create Account'

    login

    visit '/change-login'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Confirm Login', :with=>'foo@example3.com'
    click_button 'Change Login'
    page.find('#error_flash').text.must_equal "There was an error changing your login"
    page.body.must_include "logins do not match"

    visit '/change-login'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Confirm Login', :with=>'foo@example2.com'
    click_button 'Change Login'
    page.find('#error_flash').text.must_equal "There was an error changing your login"
    page.body.must_include "invalid login, already an account with this login"

    visit '/change-login'
    fill_in 'Login', :with=>'foo@example3.com'
    fill_in 'Confirm Login', :with=>'foo@example3.com'
    click_button 'Change Login'
    link = email_link(/(\/verify-login-change\?key=.+)$/, 'foo@example3.com')

    logout

    DB[:accounts].where(:email=>'foo@example2.com').update(:email=>'foo@example3.com')

    visit link
    click_button 'Verify Login Change'
    page.find('#error_flash').text.must_equal "Unable to change login as there is already an account with the new login"
    page.current_path.must_equal '/login'

    visit link
    page.find('#error_flash').text.must_equal "There was an error verifying your login change: invalid verify login change key"
  end

  it "should handle uniqueness errors raised when inserting verify login change entry" do
    unique = false
    rodauth do
      enable :login, :logout, :verify_login_change
      change_login_requires_password? false

      auth_class_eval do
        define_method(:raised_uniqueness_violation) do |*a, &block|
          unique.call if unique
          super(*a, &block)
        end
        private :raised_uniqueness_violation
      end
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
    end

    login

    visit '/change-login'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Change Login'
    email_link(/(\/verify-login-change\?key=.+)$/, 'foo@example2.com')
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your login change"

    unique = lambda{DB[:account_login_change_keys].update(:login=>'foo@example3.com'); true}
    visit '/change-login'
    fill_in 'Login', :with=>'foo@example2.com'
    proc{click_button 'Change Login'}.must_raise Sequel::ConstraintViolation
  end

  [true, false].each do |before|
    it "should clear verify login change token when closing account, when loading verify_login_change #{before ? "before" : "after"}" do
      rodauth do
        features = [:close_account, :verify_login_change]
        features.reverse! if before
        enable :login, *features
        change_login_requires_password? false
      end
      roda do |r|
        r.rodauth
        r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
      end

      login

      visit '/change-login'
      fill_in 'Login', :with=>'foo@example2.com'
      click_button 'Change Login'
      email_link(/key=.+$/, 'foo@example2.com').wont_be_nil

      DB[:account_login_change_keys].count.must_equal 1
      visit '/close-account'
      fill_in 'Password', :with=>'0123456789'
      click_button 'Close Account'
      DB[:account_login_change_keys].count.must_equal 0
    end
  end

  [:jwt, :json].each do |json|
    it "should support verifying login changes for accounts via #{json}" do
      rodauth do
        enable :login, :verify_login_change
        change_login_requires_password? false
        verify_login_change_email_body{verify_login_change_email_link}
      end
      roda(json) do |r|
        r.rodauth
      end

      json_login

      res = json_request('/change-login', :login=>'foo2@example.com')
      res.must_equal [200, {'success'=>"An email has been sent to you with a link to verify your login change"}]
      link = email_link(/key=.+$/, 'foo2@example.com')

      res = json_request('/change-login', :login=>'foo2@example.com')
      res.must_equal [200, {'success'=>"An email has been sent to you with a link to verify your login change"}]
      email_link(/key=.+$/, 'foo2@example.com').must_equal link

      res = json_request('/change-login', :login=>'foo3@example.com')
      res.must_equal [200, {'success'=>"An email has been sent to you with a link to verify your login change"}]
      new_link = email_link(/key=.+$/, 'foo3@example.com')
      new_link.wont_equal link

      res = json_request('/verify-login-change')
      res.must_equal [401, {"error"=>"Unable to verify login change"}]

      res = json_request('/verify-login-change', :key=>link[4..-1])
      res.must_equal [401, {"error"=>"Unable to verify login change"}]

      res = json_request('/verify-login-change', :key=>new_link[4..-1])
      res.must_equal [200, {"success"=>"Your login change has been verified"}]

      res = json_request("/login", :login=>'foo@example.com', :password=>'0123456789')
      res.must_equal [401, {'error'=>"There was an error logging in", "field-error"=>["login", "no matching login"]}]

      json_login(:login=>'foo3@example.com')
    end
  end
end
