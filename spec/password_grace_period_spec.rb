require File.expand_path("spec_helper", File.dirname(__FILE__))

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
  end

  it "should not ask for password again directly after creating an account" do
    rodauth do
      enable :create_account, :change_login, :password_grace_period
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

  it "should not ask for password again directly after resetting a password" do
    rodauth do
      enable :login, :reset_password, :change_login, :password_grace_period
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

