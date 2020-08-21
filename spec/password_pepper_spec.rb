require_relative 'spec_helper'

describe 'Rodauth password_pepper feature' do
  [true, false].each do |ph|
    it "should use password pepper on login when account_password_hash_column is #{ph}" do
      pepper = "secret"
      previous_peppers = [""]
      rodauth do
        enable :login, :logout, :password_pepper
        password_pepper { pepper }
        account_password_hash_column :ph if ph
      end
      roda do |r|
        r.rodauth
        next unless rodauth.logged_in?
        r.root{view :content=>"Logged In"}
      end

      login
      page.html.must_include "Logged In"

      pepper = nil
      logout
      login
      page.find("#error_flash").text.must_equal "There was an error logging in"
    end

    it "should support rotating password pepper when account_password_hash_column is #{ph}" do
      pepper = "secret"
      previous_peppers = [""]
      rodauth do
        enable :login, :logout, :password_pepper
        password_pepper { pepper }
        previous_password_peppers { previous_peppers }
        account_password_hash_column :ph if ph
      end
      roda do |r|
        r.rodauth
        next unless rodauth.logged_in?
        r.root{view :content=>"Logged In"}
      end

      login
      page.html.must_include "Logged In"

      previous_peppers = []
      logout
      login
      page.html.must_include "Logged In"

      previous_peppers = [pepper]
      pepper = "new secret"
      logout
      login
      page.html.must_include "Logged In"

      previous_peppers = []
      logout
      login
      page.html.must_include "Logged In"

      pepper = "new new secret"
      logout
      login
      page.find("#error_flash").text.must_equal "There was an error logging in"
    end

    it "should support not updating old peppers when account_password_hash_column is #{ph}" do
      pepper = "secret"
      previous_peppers = [""]
      rodauth do
        enable :change_password, :login, :logout, :password_pepper
        password_pepper { pepper }
        previous_password_peppers { previous_peppers }
        password_pepper_update? false
        account_password_hash_column :ph if ph
      end
      roda do |r|
        r.rodauth
        next unless rodauth.logged_in?
        r.root{view :content=>"Logged In"}
      end

      login
      page.html.must_include "Logged In"

      previous_peppers = []
      logout
      login
      page.find("#error_flash").text.must_equal "There was an error logging in"
    end

    it "should use password pepper when changing password when account_password_hash_column is #{ph}" do
      pepper = nil
      rodauth do
        enable :login, :logout, :password_pepper, :change_password
        password_pepper { pepper }
        previous_password_peppers []
        change_password_requires_password? false
        account_password_hash_column :ph if ph
      end
      roda do |r|
        r.rodauth
        next unless rodauth.logged_in?
        r.root{view :content=>"Logged In"}
      end

      login
      page.html.must_include "Logged In"

      pepper = "secret"
      visit "/change-password"
      fill_in "New Password", with: "new password"
      fill_in "Confirm Password", with: "new password"
      click_on "Change Password"
      page.find("#notice_flash").text.must_equal "Your password has been changed"

      logout
      login(pass: "new password")
      page.html.must_include "Logged In"

      pepper = nil
      logout
      login(pass: "new password")
      page.find("#error_flash").text.must_equal "There was an error logging in"
    end

    it "should use password pepper when resetting password when account_password_hash_column is #{ph}" do
      pepper = "secret"
      rodauth do
        enable :login, :logout, :password_pepper, :reset_password
        password_pepper { pepper }
        previous_password_peppers []
        reset_password_email_sent_redirect "/login"
        reset_password_redirect "/login"
        account_password_hash_column :ph if ph
      end
      roda do |r|
        r.rodauth
        next unless rodauth.logged_in?
        r.root{view :content=>"Logged In"}
      end

      visit "/reset-password-request"
      fill_in "Login", with: "foo@example.com"
      click_on "Request Password Reset"
      page.find("#notice_flash").text.must_equal "An email has been sent to you with a link to reset the password for your account"

      visit email_link(/(\/reset-password\?key=.+)$/)
      fill_in "Password", with: "new password"
      fill_in "Confirm Password", with: "new password"
      click_on "Reset Password"
      page.find("#notice_flash").text.must_equal "Your password has been reset"

      login(pass: "new password")
      page.html.must_include "Logged In"

      pepper = nil
      logout
      login(pass: "new password")
      page.find("#error_flash").text.must_equal "There was an error logging in"
    end

    it "should work without setting password pepper when account_password_hash_column is #{ph}" do
      rodauth do
        enable :login, :logout, :password_pepper, :change_password
        change_password_requires_password? false
        account_password_hash_column :ph if ph
      end
      roda do |r|
        r.rodauth
        next unless rodauth.logged_in?
        r.root{view :content=>"Logged In"}
      end

      login
      page.html.must_include "Logged In"

      visit '/change-password'
      fill_in 'New Password', :with=>"new password"
      fill_in 'Confirm Password', :with=>"new password"
      click_on 'Change Password'
      page.find('#notice_flash').text.must_equal "Your password has been changed"

      logout
      login(pass: "new password")
      page.html.must_include "Logged In"
    end
  end

  it "should work with disallow_password_reuse feature" do
    pepper = nil
    previous_peppers = [""]
    rodauth do
      enable :login, :logout, :change_password, :disallow_password_reuse, :password_pepper
      password_pepper { pepper }
      previous_password_peppers { previous_peppers }
      change_password_requires_password? false
    end
    roda do |r|
      r.rodauth
      next unless rodauth.logged_in?
      r.root{view :content=>"Logged In"}
    end

    login
    page.html.must_include "Logged In"

    visit '/change-password'
    fill_in 'New Password', :with=>"password_1"
    fill_in 'Confirm Password', :with=>"password_1"
    click_on 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"

    pepper = "secret_1"
    visit '/change-password'
    fill_in 'New Password', :with=>"password_2"
    fill_in 'Confirm Password', :with=>"password_2"
    click_on 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"

    previous_peppers.unshift pepper
    pepper = "secret_2"
    visit '/change-password'
    fill_in 'New Password', :with=>"password_3"
    fill_in 'Confirm Password', :with=>"password_3"
    click_on 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"

    visit '/change-password'
    fill_in 'New Password', :with=>"password_2"
    fill_in 'Confirm Password', :with=>"password_2"
    click_on 'Change Password'
    page.find('#error_flash').text.must_equal "There was an error changing your password"

    previous_peppers.shift
    visit '/change-password'
    fill_in 'New Password', :with=>"password_2"
    fill_in 'Confirm Password', :with=>"password_2"
    click_on 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"

    visit '/change-password'
    fill_in 'New Password', :with=>"password_1"
    fill_in 'Confirm Password', :with=>"password_1"
    click_on 'Change Password'
    page.find('#error_flash').text.must_equal "There was an error changing your password"

    previous_peppers.shift
    visit '/change-password'
    fill_in 'New Password', :with=>"password_1"
    fill_in 'Confirm Password', :with=>"password_1"
    click_on 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"
  end
end
