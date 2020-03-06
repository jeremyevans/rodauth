require_relative 'spec_helper'

describe 'Rodauth verify_change_login feature' do
  it "should support reverifying accounts after changing logins" do
    rodauth do
      enable :login, :verify_change_login
      change_login_requires_password? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In#{rodauth.verified_account?}" : "Not Logged"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Confirm Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Create Account'
    link = email_link(/(\/verify-account\?key=.+)$/, 'foo@example2.com')

    visit '/change-login'
    page.find('#error_flash').text.must_equal "Cannot change login for unverified account. Please verify this account before changing the login."
    page.current_path.must_equal '/'

    visit link
    click_button 'Verify Account'
    page.find('#notice_flash').text.must_equal "Your account has been verified"
    page.body.must_include('Logged Intrue')

    visit '/change-login'
    fill_in 'Login', :with=>'foo3@example.com'
    fill_in 'Confirm Login', :with=>'foo3@example.com'
    click_button 'Change Login'
    page.find('#notice_flash').text.must_equal "Your login has been changed. An email has been sent to you with a link to verify your account"
    page.current_path.must_equal '/'
    page.body.must_include('Logged Infalse')
    link2 = email_link(/(\/verify-account\?key=.+)$/, 'foo3@example.com')
    link2.wont_equal link

    visit link2
    click_button 'Verify Account'
    page.find('#notice_flash').text.must_equal "Your account has been verified"
    page.body.must_include('Logged Intrue')
  end
end
