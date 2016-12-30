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

    login(:pass=>'012345678910')
    page.find('#error_flash').text.must_equal 'There was an error logging in'

    login
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.body.must_include("Logged In")

    remove_cookie('rack.session')

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    2.times do
      fill_in 'Password', :with=>'012345678910'
      click_button 'Login'
      page.find('#error_flash').text.must_equal 'There was an error logging in'
    end

    fill_in 'Password', :with=>'012345678910'
    click_button 'Login'
    page.find('#error_flash').text.must_equal "This account is currently locked out and cannot be logged in to."
    page.body.must_include("This account is currently locked out")
    click_button 'Request Account Unlock'
    page.find('#notice_flash').text.must_equal 'An email has been sent to you with a link to unlock your account'

    link = email_link(/(\/unlock-account\?key=.+)$/)
    visit link[0...-1]
    page.find('#error_flash').text.must_equal 'No matching unlock account key'

    visit link
    click_button 'Unlock Account'
    page.find('#notice_flash').text.must_equal 'Your account has been unlocked'
    page.body.must_include('Not Logged')

    login
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.body.must_include("Logged In")
  end

  it "should support account lockouts with autologin and password required on unlock" do
    rodauth do
      enable :lockout
      unlock_account_requires_password? true
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>(rodauth.logged_in? ? "Logged In" : "Not Logged")}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    100.times do
      fill_in 'Password', :with=>'012345678910'
      click_button 'Login'
      page.find('#error_flash').text.must_equal 'There was an error logging in'
    end

    fill_in 'Password', :with=>'012345678910'
    click_button 'Login'
    page.find('#error_flash').text.must_equal "This account is currently locked out and cannot be logged in to."
    page.body.must_include("This account is currently locked out")
    click_button 'Request Account Unlock'
    page.find('#notice_flash').text.must_equal 'An email has been sent to you with a link to unlock your account'

    link = email_link(/(\/unlock-account\?key=.+)$/)
    visit link
    click_button 'Unlock Account'

    page.find('#error_flash').text.must_equal 'There was an error unlocking your account'
    page.body.must_include('invalid password')
    fill_in 'Password', :with=>'0123456789'
    click_button 'Unlock Account'

    page.find('#notice_flash').text.must_equal 'Your account has been unlocked'
    page.body.must_include("Logged In")
  end

  it "should autounlock after enough time" do
    rodauth do
      enable :lockout
      max_invalid_logins 2
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>(rodauth.logged_in? ? "Logged In" : "Not Logged")}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    2.times do
      fill_in 'Password', :with=>'012345678910'
      click_button 'Login'
      page.find('#error_flash').text.must_equal 'There was an error logging in'
    end
    fill_in 'Password', :with=>'012345678910'
    click_button 'Login'
    page.find('#error_flash').text.must_equal "This account is currently locked out and cannot be logged in to."
    page.body.must_include("This account is currently locked out")
    DB[:account_lockouts].update(:deadline=>Date.today - 3)

    login
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.body.must_include("Logged In")
  end

  it "should clear unlock token when closing account" do
    rodauth do
      enable :lockout, :close_account
      max_invalid_logins 2
    end
    roda do |r|
      r.get('b') do
        session[:account_id] = DB[:accounts].get(:id)
        'b'
      end
      r.rodauth
      r.root{view :content=>(rodauth.logged_in? ? "Logged In" : "Not Logged")}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    3.times do
      fill_in 'Password', :with=>'012345678910'
      click_button 'Login'
    end
    DB[:account_lockouts].count.must_equal 1
    
    visit 'b'

    visit '/close-account'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Close Account'
    DB[:account_lockouts].count.must_equal 0
  end

  it "should handle uniqueness errors raised when inserting unlock account token" do
    rodauth do
      enable :lockout
      max_invalid_logins 2
    end
    roda do |r|
      def rodauth.raised_uniqueness_violation(*) super; true; end
      r.rodauth
      r.root{view :content=>(rodauth.logged_in? ? "Logged In" : "Not Logged")}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'012345678910'
    click_button 'Login'
    page.find('#error_flash').text.must_equal 'There was an error logging in'

    fill_in 'Password', :with=>'012345678910'
    click_button 'Login'
    page.find('#error_flash').text.must_equal "This account is currently locked out and cannot be logged in to."
    page.body.must_include("This account is currently locked out")
    click_button 'Request Account Unlock'
    page.find('#notice_flash').text.must_equal 'An email has been sent to you with a link to unlock your account'

    link = email_link(/(\/unlock-account\?key=.+)$/)
    visit link
    click_button 'Unlock Account'
    page.find('#notice_flash').text.must_equal 'Your account has been unlocked'
    page.body.must_include("Logged In")
  end

  it "should support account lockouts via jwt" do
    rodauth do
      enable :logout, :lockout
      max_invalid_logins 2
      unlock_account_autologin? false
      unlock_account_email_body{unlock_account_email_link}
    end
    roda(:jwt) do |r|
      r.rodauth
      [rodauth.logged_in? ? "Logged In" : "Not Logged"]
    end

    res = json_request('/unlock-account-request', :login=>'foo@example.com')
    res.must_equal [401, {'error'=>"no matching login"}]

    res = json_login(:pass=>'1', :no_check=>true)
    res.must_equal [401, {'error'=>"There was an error logging in", "field-error"=>["password", "invalid password"]}]

    json_login
    json_logout

    2.times do
      res = json_login(:pass=>'1', :no_check=>true)
      res.must_equal [401, {'error'=>"There was an error logging in", "field-error"=>["password", "invalid password"]}]
    end

    2.times do
      res = json_login(:pass=>'1', :no_check=>true)
      res.must_equal [403, {'error'=>"This account is currently locked out and cannot be logged in to."}]
    end

    res = json_request('/unlock-account')
    res.must_equal [401, {'error'=>"No matching unlock account key"}]

    res = json_request('/unlock-account-request', :login=>'foo@example.com')
    res.must_equal [200, {'success'=>"An email has been sent to you with a link to unlock your account"}]

    link = email_link(/key=.+$/)
    res = json_request('/unlock-account', :key=>link[4...-1])
    res.must_equal [401, {'error'=>"No matching unlock account key"}]

    res = json_request('/unlock-account', :key=>link[4..-1])
    res.must_equal [200, {'success'=>"Your account has been unlocked"}]

    res = json_request.must_equal [200, ['Not Logged']]

    json_login
  end
end
