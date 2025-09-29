require_relative 'spec_helper'

describe 'Rodauth lockout feature' do
  it "should support account lockouts without autologin on unlock" do
    lockouts = []
    rodauth do
      enable :lockout
      max_invalid_logins 2
      unlock_account_autologin? false
      after_account_lockout{lockouts << true}
      account_lockouts_email_last_sent_column nil
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
    lockouts.must_equal [true]

    fill_in 'Password', :with=>'012345678910'
    click_button 'Login'
    page.find('#error_flash').text.must_equal "This account is currently locked out and cannot be logged in to"
    page.body.must_include("This account is currently locked out")
    page.status_code.must_equal 403
    click_button 'Request Account Unlock'
    page.find('#notice_flash').text.must_equal 'An email has been sent to you with a link to unlock your account'
    link = email_link(/(\/unlock-account\?key=.+)$/)

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'012345678910'
    click_button 'Login'
    click_button 'Request Account Unlock'
    email_link(/(\/unlock-account\?key=.+)$/).must_equal link

    visit '/unlock-account'
    page.find('#error_flash').text.must_equal "There was an error unlocking your account: invalid or expired unlock account key"

    visit link[0...-1]
    page.find('#error_flash').text.must_equal "There was an error unlocking your account: invalid or expired unlock account key"

    if DB[:accounts].get(:id).is_a?(Integer)
      visit link.sub('key=', 'key=18446744073709551616')
      page.find('#error_flash').text.must_equal "There was an error unlocking your account: invalid or expired unlock account key"

      visit link.sub('key=', 'key=-18446744073709551616')
      page.find('#error_flash').text.must_equal "There was an error unlocking your account: invalid or expired unlock account key"

      visit link.sub('key=', 'key=v')
      page.find('#error_flash').text.must_equal "There was an error unlocking your account: invalid or expired unlock account key"
    end

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
    page.find('#error_flash').text.must_equal "This account is currently locked out and cannot be logged in to"
    page.body.must_include("This account is currently locked out")
    click_button 'Request Account Unlock'
    page.find('#notice_flash').text.must_equal 'An email has been sent to you with a link to unlock your account'
    link = email_link(/(\/unlock-account\?key=.+)$/)

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'012345678910'
    click_button 'Login'
    click_button 'Request Account Unlock'
    page.find('#error_flash').text.must_equal "An email has recently been sent to you with a link to unlock the account"
    Mail::TestMailer.deliveries.must_equal []

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
      convert_token_id_to_integer? false
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
    page.find('#error_flash').text.must_equal "This account is currently locked out and cannot be logged in to"
    page.body.must_include("This account is currently locked out")
    DB[:account_lockouts].update(:deadline=>Date.today - 3)

    login
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.body.must_include("Logged In")
  end

  it "should change unlock key when changing login" do
    rodauth do
      enable :login, :lockout, :change_login
      require_login_confirmation? false
      change_login_requires_password? false
      max_invalid_logins 2
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In!" : "Not Logged"}
    end

    login
    session1 = get_cookie('rack.session')
    remove_cookie('rack.session')

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    3.times do
      fill_in 'Password', :with=>'012345678910'
      click_button 'Login'
    end
    page.find('#error_flash').text.must_equal "This account is currently locked out and cannot be logged in to"

    set_cookie('rack.session', session1)
    visit '/change-login'
    fill_in 'Login', :with=>'foo3@example.com'
    key1 = DB[:account_lockouts].get(:key)
    key1.must_be_kind_of String
    click_button 'Change Login'
    page.find('#notice_flash').text.must_equal "Your login has been changed"
    key2 = DB[:account_lockouts].get(:key)
    key2.must_be_kind_of String
    key1.wont_equal key2
  end

  [true, false].each do |before|
    it "should clear unlock token when closing account, when loading lockout #{before ? "before" : "after"}" do
      rodauth do
        features = [:close_account, :lockout]
        features.reverse! if before
        enable(*features)
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
  end

  it "should handle uniqueness errors raised when inserting unlock account token" do
    lockouts = []
    rodauth do
      enable :lockout
      max_invalid_logins 2
      after_account_lockout{lockouts << true}
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
    lockouts.must_equal [true]
    page.find('#error_flash').text.must_equal "This account is currently locked out and cannot be logged in to"
    page.body.must_include("This account is currently locked out")
    click_button 'Request Account Unlock'
    page.find('#notice_flash').text.must_equal 'An email has been sent to you with a link to unlock your account'

    link = email_link(/(\/unlock-account\?key=.+)$/)
    visit link
    click_button 'Unlock Account'
    page.find('#notice_flash').text.must_equal 'Your account has been unlocked'
    page.body.must_include("Logged In")
  end

  it "should reraise uniqueness errors raised when inserting unlock account token if no token found" do
    lockouts = []
    rodauth do
      enable :lockout
      max_invalid_logins 2
      after_account_lockout{lockouts << true}
    end
    roda do |r|
      def rodauth.raised_uniqueness_violation(*, &_) ArgumentError.new; end
      r.rodauth
      r.root{view :content=>(rodauth.logged_in? ? "Logged In" : "Not Logged")}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'012345678910'
    click_button 'Login'
    page.find('#error_flash').text.must_equal 'There was an error logging in'

    fill_in 'Password', :with=>'012345678910'
    proc{click_button 'Login'}.must_raise ArgumentError
  end

  [:jwt, :json].each do |json|
    it "should support account lockouts via #{json}" do
      rodauth do
        enable :logout, :lockout
        max_invalid_logins 2
        unlock_account_autologin? false
        unlock_account_email_body{unlock_account_email_link}
      end
      roda(json) do |r|
        r.rodauth
        [rodauth.logged_in? ? "Logged In" : "Not Logged"]
      end

      res = json_request('/unlock-account-request', :login=>'foo@example.com')
      res.must_equal [401, {'reason'=>'no_matching_login', 'error'=>"No matching login"}]

      res = json_login(:pass=>'1', :no_check=>true)
      res.must_equal [401, {'reason'=>"invalid_password",'error'=>"There was an error logging in", "field-error"=>["password", "invalid password"]}]

      json_login
      json_logout

      2.times do
        res = json_login(:pass=>'1', :no_check=>true)
        res.must_equal [401, {'reason'=>"invalid_password",'error'=>"There was an error logging in", "field-error"=>["password", "invalid password"]}]
      end

      2.times do
        res = json_login(:pass=>'1', :no_check=>true)
        res.must_equal [403, {'reason'=>"account_locked_out", 'error'=>"This account is currently locked out and cannot be logged in to"}]
      end

      res = json_request('/unlock-account')
      res.must_equal [401, {'reason'=>'invalid_unlock_account_key', 'error'=>"There was an error unlocking your account: invalid or expired unlock account key"}]

      res = json_request('/unlock-account-request', :login=>'foo@example.com')
      res.must_equal [200, {'success'=>"An email has been sent to you with a link to unlock your account"}]

      link = email_link(/key=.+$/)
      res = json_request('/unlock-account', :key=>link[4...-1])
      res.must_equal [401, {'reason'=>'invalid_unlock_account_key', 'error'=>"There was an error unlocking your account: invalid or expired unlock account key"}]

      res = json_request('/unlock-account', :key=>link[4..-1])
      res.must_equal [200, {'success'=>"Your account has been unlocked"}]

      res = json_request.must_equal [200, ['Not Logged']]

      json_login
    end
  end

  it "should support account locks, unlocks, and unlock requests using internal requests" do
    rodauth do
      enable :lockout, :logout, :internal_request
      account_lockouts_email_last_sent_column nil
      domain 'example.com'
      internal_request_configuration do
        csrf_tag { |*| fail "must not rely on Roda session" }
      end
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>(rodauth.logged_in? ? "Logged In" : "Not Logged")}
    end

    proc do
      app.rodauth.lock_account(:account_login=>'foo3@example.com')
    end.must_raise Rodauth::InternalRequestError

    proc do
      app.rodauth.unlock_account_request(:account_login=>'foo3@example.com')
    end.must_raise Rodauth::InternalRequestError

    proc do
      app.rodauth.unlock_account(:account_login=>'foo3@example.com')
    end.must_raise Rodauth::InternalRequestError

    proc do
      app.rodauth.unlock_account_request(:login=>'foo@example.com')
    end.must_raise Rodauth::InternalRequestError

    proc do
      app.rodauth.unlock_account_request(:account_login=>'foo@example.com')
    end.must_raise Rodauth::InternalRequestError

    proc do
      app.rodauth.unlock_account(:account_login=>'foo@example.com')
    end.must_raise Rodauth::InternalRequestError

    app.rodauth.lock_account(:account_login=>'foo@example.com').must_be_nil

    # Check idempotent
    app.rodauth.lock_account(:account_login=>'foo@example.com').must_be_nil

    login
    page.find('#error_flash').text.must_equal "This account is currently locked out and cannot be logged in to"

    app.rodauth.unlock_account_request(:login=>'foo@example.com').must_be_nil
    link = email_link(/(\/unlock-account\?key=.+)$/)

    app.rodauth.unlock_account_request(:account_login=>'foo@example.com').must_be_nil
    link2 = email_link(/(\/unlock-account\?key=.+)$/)
    link2.must_equal link

    visit link
    click_button 'Unlock Account'

    page.find('#notice_flash').text.must_equal 'Your account has been unlocked'
    page.body.must_include("Logged In")

    logout

    app.rodauth.lock_account(:account_login=>'foo@example.com').must_be_nil

    login
    page.find('#error_flash').text.must_equal "This account is currently locked out and cannot be logged in to"

    app.rodauth.unlock_account(:account_login=>'foo@example.com').must_be_nil

    login
    page.body.must_include 'Logged In'

    app.rodauth.lock_account(:account_login=>'foo@example.com').must_be_nil

    proc do
      app.rodauth.login(login: 'foo@example.com', password: "0123456789")
    end.must_raise Rodauth::InternalRequestError

    app.rodauth.unlock_account_request(:account_login=>'foo@example.com').must_be_nil
    link3 = email_link(/(\/unlock-account\?key=.+)$/)
    link3.wont_equal link2
    key = link3.split('=').last

    proc do
      app.rodauth.unlock_account(:unlock_account_key=>key[0...-1])
    end.must_raise Rodauth::InternalRequestError

    app.rodauth.unlock_account(:unlock_account_key=>key).must_be_nil

    login
    page.body.must_include 'Logged In'
  end
end
