require_relative 'spec_helper'

describe 'Rodauth password grace period feature' do
  it "should not ask for password again if password was recently entered" do
    grace = 300
    rodauth do
      enable :login, :change_login, :password_grace_period
      password_grace_period{grace}
      require_login_confirmation? false
    end
    roda do |r|
      r.rodauth
      r.get("reset"){session.delete(rodauth.last_password_entry_session_key); ""}
      r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
    end

    login
    page.body.must_include "Logged In"

    visit '/change-login'
    fill_in 'Login', :with=>'foo2@example.com'
    click_button 'Change Login'
    page.find('#notice_flash').text.must_equal "Your login has been changed"

    grace = -1
    visit '/change-login'
    fill_in 'Login', :with=>'foo3@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Change Login'
    page.find('#notice_flash').text.must_equal "Your login has been changed"

    grace = 300
    visit '/change-login'
    grace = -1
    fill_in 'Login', :with=>'foo4@example.com'
    click_button 'Change Login'
    page.find('#error_flash').text.must_equal "There was an error changing your login"
    page.html.must_include("invalid password")

    fill_in 'Password', :with=>'0123456789'
    click_button 'Change Login'
    page.find('#notice_flash').text.must_equal "Your login has been changed"

    visit '/reset'
    visit '/change-login'
    fill_in 'Login', :with=>'foo5@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Change Login'
    page.find('#notice_flash').text.must_equal "Your login has been changed"
  end

  [true, false].each do |before|
    it "should not ask for password again directly after creating an account, when loading password_grace_period #{before ? "before" : "after"}" do
      rodauth do
        features = [:create_account, :password_grace_period]
        features.reverse! if before
        enable :change_login, *features
        require_login_confirmation? false
      end
      roda do |r|
        r.rodauth
        r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
      end

      visit '/create-account'
      fill_in 'Login', :with=>'foo2@example.com'
      fill_in 'Password', :with=>'apple2'
      fill_in 'Confirm Password', :with=>'apple2'
      click_button 'Create Account'

      visit '/change-login'
      fill_in 'Login', :with=>'foo3@example.com'
      click_button 'Change Login'
      page.find('#notice_flash').text.must_equal "Your login has been changed"
    end

    it "should not ask for password again directly after resetting a password, when loading password_grace_period #{before ? "before" : "after"}" do
      rodauth do
        features = [:reset_password, :password_grace_period]
        features.reverse! if before
        enable :login, :change_login, *features
        require_login_confirmation? false
        reset_password_autologin? true
      end
      roda do |r|
        r.rodauth
        r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
      end

      login(:pass=>'01234567')
      click_button 'Request Password Reset'
      link = email_link(/(\/reset-password\?key=.+)$/)
      visit link
      fill_in 'Password', :with=>'0123456'
      fill_in 'Confirm Password', :with=>'0123456'
      click_button 'Reset Password'
      page.find('#notice_flash').text.must_equal "Your password has been reset"
      page.current_path.must_equal '/'

      visit '/change-login'
      fill_in 'Login', :with=>'foo2@example.com'
      click_button 'Change Login'
      page.find('#notice_flash').text.must_equal "Your login has been changed"
    end
  end

  it "should ask for password after logging in via remember token" do
    rodauth do
      enable :login, :remember, :change_login, :password_grace_period
      require_login_confirmation? false
    end
    roda do |r|
      r.rodauth
      rodauth.load_memory
      r.root do
        if rodauth.logged_in?
          if rodauth.logged_in_via_remember_key?
            view(:content=>"Logged In via Remember")
          else
            "Logged In Normally"
          end
        else
          "Not Logged In"
        end
      end
    end

    login

    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_include "Logged In via Remember"

    visit '/change-login'
    fill_in 'Login', :with=>'foo3@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Change Login'
    page.find('#notice_flash').text.must_equal "Your login has been changed"
  end

  it "should not extend grace period trying to change password using existing password" do
    rodauth do
      enable :login, :change_password, :password_grace_period
    end
    roda do |r|
      r.rodauth
      r.get "grace-period-get" do
        session[rodauth.last_password_entry_session_key].to_s
      end
      r.get "grace-period-set" do
        session[rodauth.last_password_entry_session_key] = Time.now.to_i - 100
        ''
      end
      r.root do
        view :content=>"Not Logged In"
      end
    end

    login

    visit '/grace-period-set'
    visit '/grace-period-get'
    t = Integer(page.body, 10)

    visit '/change-password'
    fill_in 'New Password', :with=>'0123456789'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Change Password'
    page.find('#error_flash').text.must_equal "There was an error changing your password"
    page.body.must_include 'invalid password, same as current password'
    page.current_path.must_equal '/change-password'

    visit '/grace-period-get'
    Integer(page.body, 10).must_equal t

    visit '/change-password'
    fill_in 'New Password', :with=>'012345678'
    fill_in 'Confirm Password', :with=>'012345678'
    click_button 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"
    page.current_path.must_equal '/'
  end
end
