require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth lockout feature' do
  it "should support account lockouts without autologin on unlock" do
    rodauth do
      enable :lockout
      max_invalid_logins 2
      unlock_account_autologin? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>(rodauth.logged_in? ? "Logged In" : "Not Logged")}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'012345678910'
    click_button 'Login'
    page.find('#error_flash').text.must_equal 'There was an error logging in'

    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.body.must_match(/Logged In/)

    remove_cookie('rack.session')

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    3.times do
      fill_in 'Password', :with=>'012345678910'
      click_button 'Login'
      page.find('#error_flash').text.must_equal 'There was an error logging in'
    end
    page.body.must_match(/This account is currently locked out/)
    click_button 'Request Account Unlock'
    page.find('#notice_flash').text.must_equal 'An email has been sent to you with a link to unlock your account'

    link = email_link(/(\/unlock-account\?key=.+)$/)
    visit link[0...-1]
    page.find('#error_flash').text.must_equal 'No matching unlock account key'

    visit link
    click_button 'Unlock Account'
    page.find('#notice_flash').text.must_equal 'Your account has been unlocked'
    page.body.must_include('Not Logged')

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.body.must_match(/Logged In/)
  end

  it "should support account lockouts with autologin on unlock" do
    rodauth do
      enable :lockout
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>(rodauth.logged_in? ? "Logged In" : "Not Logged")}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    101.times do |i|
      fill_in 'Password', :with=>'012345678910'
      click_button 'Login'
      page.find('#error_flash').text.must_equal 'There was an error logging in'
    end
    page.body.must_match(/This account is currently locked out/)
    click_button 'Request Account Unlock'
    page.find('#notice_flash').text.must_equal 'An email has been sent to you with a link to unlock your account'

    link = email_link(/(\/unlock-account\?key=.+)$/)
    visit link
    click_button 'Unlock Account'
    page.body.must_match(/Logged In/)
  end
end
