require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth verify_account feature' do
  it "should support verifying accounts" do
    rodauth do
      enable :login, :create_account, :verify_account
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

    link = email_link(/(\/verify-account\?key=.+)$/)
    visit '/login'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.find('#error_flash').text.must_equal 'The account you tried to login with is currently awaiting verification'
    page.html.must_match(/If you no longer have the email to verify the account, you can request that it be resent to you/)
    click_button 'Send Verification Email Again'
    page.current_path.must_equal '/login'

    email_link(/(\/verify-account\?key=.+)$/).must_equal link
    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Create Account'
    click_button 'Send Verification Email Again'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    page.current_path.must_equal '/login'

    link = email_link(/(\/verify-account\?key=.+)$/)
    visit link[0...-1]
    page.find('#error_flash').text.must_equal "invalid verify account key"

    visit link
    click_button 'Verify Account'
    page.find('#notice_flash').text.must_equal "Your account has been verified"
    page.current_path.must_equal '/'

    visit '/login'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.current_path.must_equal '/'
  end

  it "should support autologin when verifying accounts" do
    rodauth do
      enable :login, :create_account, :verify_account
      verify_account_autologin? true
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
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    page.current_path.must_equal '/'

    link = email_link(/(\/verify-account\?key=.+)$/)
    visit link
    click_button 'Verify Account'
    page.find('#notice_flash').text.must_equal "Your account has been verified"
    page.body.must_match /Logged In/
  end
end
