require_relative 'spec_helper'

describe 'Rodauth remember feature' do
  it "should support login via remember token" do
    secret = old_secret = nil
    raw_before = Time.now - 100000000
    rodauth do
      enable :login, :remember
      hmac_secret{secret}
      hmac_old_secret{old_secret}
      raw_remember_token_deadline{raw_before}
    end
    roda do |r|
      r.rodauth
      r.get 'load' do
        rodauth.load_memory
        r.redirect '/'
      end
      r.get 'loadpage' do
        rodauth.load_memory
        ''
      end
      r.root do
        if rodauth.logged_in?
          if rodauth.logged_in_via_remember_key?
            view :content=>"Logged In via Remember"
          else
            view :content=>"Logged In Normally"
          end
        else
          view :content=>"Not Logged In"
        end
      end
    end

    visit '/loadpage'
    page.response_headers.wont_include 'Set-Cookie'

    login
    page.body.must_include 'Logged In Normally'

    visit '/load'
    page.body.must_include 'Logged In Normally'

    visit '/remember'
    click_button 'Change Remember Setting'
    page.find('#error_flash').text.must_equal "There was an error updating your remember setting"

    choose 'Remember Me'
    click_button 'Change Remember Setting'
    page.find('#notice_flash').text.must_equal "Your remember setting has been updated"
    page.body.must_include 'Logged In Normally'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_include 'Not Logged In'

    secret = SecureRandom.random_bytes(32)
    visit '/load'
    page.body.must_include 'Not Logged In'

    secret = nil
    raw_before = Time.now + 100000000
    login
    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    remove_cookie('rack.session')

    secret = SecureRandom.random_bytes(32)
    visit '/load'
    page.body.must_include 'Logged In via Remember'

    key = get_cookie('_remember')
    visit '/remember'
    choose 'Forget Me'
    click_button 'Change Remember Setting'
    page.body.must_include 'Logged In via Remember'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_include 'Not Logged In'

    visit '/load'
    page.body.must_include 'Not Logged In'

    set_cookie('_remember', key.gsub('_', '-'))
    visit '/load'
    page.body.must_include 'Not Logged In'

    set_cookie('_remember', key)
    visit '/load'
    page.body.must_include 'Logged In via Remember'

    visit '/remember'
    choose 'Disable Remember Me'
    click_button 'Change Remember Setting'
    page.body.must_include 'Logged In via Remember'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_include 'Not Logged In'

    set_cookie('_remember', key)
    visit '/load'
    page.body.must_include 'Not Logged In'

    login
    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'

    secret = SecureRandom.random_bytes(32)
    remove_cookie('rack.session')
    visit '/load'
    page.body.must_include 'Not Logged In'

    login
    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    remove_cookie('rack.session')
    visit '/load'
    page.body.must_include 'Logged In via Remember'

    old_secret = secret
    secret = SecureRandom.random_bytes(32)
    remove_cookie('rack.session')
    visit '/load'
    page.body.must_include 'Logged In via Remember'

    old_secret = nil
    remove_cookie('rack.session')
    visit '/load'
    page.body.must_include 'Logged In via Remember'

    old_secret = SecureRandom.random_bytes(32)
    secret = SecureRandom.random_bytes(32)
    remove_cookie('rack.session')
    visit '/load'
    page.body.must_include 'Not Logged In'
  end

  [true, false].each do |before|
    it "should forget remember token when explicitly logging out, when loading remember #{before ? "before" : "after"}" do
      rodauth do
        features = [:logout, :remember]
        features.reverse! if before
        enable :login, *features
      end
      roda do |r|
        r.rodauth
        r.get 'load' do
          rodauth.load_memory
          r.redirect '/'
        end
        r.root{rodauth.logged_in? ? "Logged In" : "Not Logged In"}
      end

      login
      page.body.must_equal 'Logged In'

      visit '/remember'
      choose 'Remember Me'
      click_button 'Change Remember Setting'
      page.body.must_equal 'Logged In'

      logout

      visit '/'
      page.body.must_equal 'Not Logged In'

      visit '/load'
      page.body.must_equal 'Not Logged In'
    end
  end

  it "should set safe default cookie attributes" do
    cookie_options = {}

    rodauth do
      enable :login, :remember, :logout
      remember_cookie_options { cookie_options }
      after_login { remember_login }
    end
    roda do |r|
      r.rodauth
      r.root{rodauth.logged_in? ? "Logged In" : "Not Logged In"}
    end

    login
    retrieve_cookie('_remember') do |cookie|
      cookie.to_hash["path"].must_equal '/'
      cookie.secure?.must_equal false
      cookie.http_only?.must_equal true
    end
    logout

    login :path=>Capybara.default_host.gsub("http://", "https://") + "/login"
    retrieve_cookie('_remember') do |cookie|
      cookie.secure?.must_equal true
    end
    logout

    cookie_options = {:path=>nil, :httponly=>false, :secure=>false}

    login
    retrieve_cookie('_remember') do |cookie|
      cookie.to_hash["path"].must_equal ''
      cookie.http_only?.must_equal false
    end
    logout

    login :path=>Capybara.default_host.gsub("http://", "https://") + "/login"
    retrieve_cookie('_remember') do |cookie|
      cookie.secure?.must_equal false
    end
    logout
  end

  it "should remove cookie if cookie is no longer valid" do
    rodauth do
      enable :login, :remember
      skip_status_checks? false
    end
    roda do |r|
      r.rodauth
      r.get 'load' do
        rodauth.load_memory
        r.redirect '/'
      end
      r.root do
        if rodauth.logged_in?
          if rodauth.logged_in_via_remember_key?
            view :content=>"Logged In via Remember"
          else
            view :content=>"Logged In Normally"
          end
        else
          view :content=>"Not Logged In"
        end
      end
    end

    login
    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    page.body.must_include 'Logged In Normally'

    cookie = get_cookie('_remember')
    remove_cookie('rack.session')

    rk = DB[:account_remember_keys].first
    DB[:account_remember_keys].update(:key=>rk[:key][0...-1])
    visit '/load'
    page.body.must_include 'Not Logged In'
    get_cookie('_remember').must_equal ""

    DB[:account_remember_keys].delete
    set_cookie('_remember', cookie)
    visit '/load'
    page.body.must_include 'Not Logged In'
    get_cookie('_remember').must_equal ""

    DB[:account_remember_keys].insert(rk)
    DB[:accounts].update(:status_id=>3)
    set_cookie('_remember', cookie)
    visit '/load'
    page.body.must_include 'Not Logged In'
    get_cookie('_remember').must_equal ""
    DB[:account_remember_keys].must_be :empty?
  end

  it "should support clearing remembered flag" do
    rodauth do
      enable :login, :confirm_password, :remember
      remember_cookie_options :path=>nil
    end
    roda do |r|
      r.rodauth
      r.get 'load' do
        rodauth.load_memory
        r.redirect '/'
      end
      r.get 'req-pass' do
        rodauth.require_password_authentication
        view :content=>"Password Authentication Passed"
      end
      r.root do
        if rodauth.logged_in?
          if rodauth.logged_in_via_remember_key?
            view :content=>"Logged In via Remember"
          else
            view :content=>"Logged In Normally"
          end
        else
          view :content=>"Not Logged In"
        end
      end
    end

    login
    page.body.must_include 'Logged In Normally'

    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    page.body.must_include 'Logged In Normally'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_include 'Not Logged In'

    visit '/load'
    page.body.must_include 'Logged In via Remember'

    visit '/req-pass'
    page.find('#error_flash').text.must_equal "You need to confirm your password before continuing"

    visit '/confirm-password'
    fill_in 'Password', :with=>'012345678'
    click_button 'Confirm Password'
    page.find('#error_flash').text.must_equal "There was an error confirming your password"
    page.html.must_include("invalid password")

    fill_in 'Password', :with=>'0123456789'
    click_button 'Confirm Password'
    page.find('#notice_flash').text.must_equal "Your password has been confirmed"
    page.body.must_include 'Password Authentication Passed'

    visit '/'
    page.body.must_include 'Logged In Normally'
  end

  it "should support extending remember token" do
    rodauth do
      enable :login, :remember, :logout
      extend_remember_deadline? true
      remember_period :days=>30
    end
    roda do |r|
      r.rodauth
      r.get 'load' do
        rodauth.load_memory
        r.redirect '/'
      end
      r.get 'remove' do
        session.delete(rodauth.remember_deadline_extended_session_key)
        r.redirect '/'
      end
      r.get 'expire' do
        session[rodauth.remember_deadline_extended_session_key] -= 10000
        r.redirect '/'
      end
      r.root do
        if rodauth.logged_in?
          if rodauth.logged_in_via_remember_key?
            "Logged In via Remember"
          else
            "Logged In Normally"
          end
        else
          "Not Logged In"
        end
      end
    end

    get_deadline = lambda do
      deadline = DB[:account_remember_keys].get(:deadline)
      if deadline.is_a?(String)
        # Handle jdbc-sqlite times returned as strings in UTC without offset
        deadline += '+0000' unless Date._parse(deadline).include?(:offset)
        deadline = Time.parse(deadline)
      end
      deadline
    end

    login

    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    get_deadline.call.must_be(:<, Time.now + 15*86400)

    DB[:account_remember_keys].update(deadline: Time.now + 10)
    visit '/expire'
    visit '/load'
    deadline = DB[:account_remember_keys].get(:deadline)
    deadline = Time.parse(deadline) if deadline.is_a?(String)
    deadline.must_be(:>, Time.now + 29*86400)

    remove_cookie('rack.session')
    visit '/'
    page.body.must_equal 'Not Logged In'

    old_expiration = cookie_jar.instance_variable_get(:@cookies).first.expires
    visit '/load'
    page.body.must_equal 'Logged In via Remember'
    new_expiration = cookie_jar.instance_variable_get(:@cookies).first.expires
    new_expiration.must_be :>=, old_expiration
    get_deadline.call.must_be(:>, Time.now + 29*86400)

    visit '/remove'
    DB[:account_remember_keys].update(deadline: Time.now + 10)
    visit '/load'
    get_deadline.call.must_be(:>, Time.now + 29*86400)

    visit '/expire'
    DB[:account_remember_keys].update(deadline: Time.now + 10)
    visit '/load'
    get_deadline.call.must_be(:>, Time.now + 29*86400)

    # Don't extend remember period if not logged in through remember token.
    # If someone is logging in manually and not through a remember token,
    # automatically extending the remember token they are not using increases risk.
    logout
    remove_cookie('_remember')
    DB[:account_remember_keys].update(deadline: Time.now + 10)
    login
    visit '/load'
    get_deadline.call.must_be(:<, Time.now + 20)

    # Test that load_memory doesn't fail if the account no longer exists
    # but there is still an remember cookie set.
    logout
    login
    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    visit '/expire'
    DB[:account_remember_keys].delete
    DB[PASSWORD_HASH_TABLE].delete
    DB[:accounts].delete
    visit '/load'
    page.html.must_equal "Not Logged In"
  end

  [true, false].each do |before|
    it "should clear remember token when closing account, when loading remember #{before ? "before" : "after"}" do
      rodauth do
        features = [:close_account, :remember]
        features.reverse! if before
        enable :login, *features
      end
      roda do |r|
        r.rodauth
        rodauth.load_memory
        r.root{rodauth.logged_in? ? "Logged In" : "Not Logged In"}
      end

      login

      visit '/remember'
      choose 'Remember Me'
      click_button 'Change Remember Setting'
      DB[:account_remember_keys].count.must_equal 1

      visit '/close-account'
      fill_in 'Password', :with=>'0123456789'
      click_button 'Close Account'
      DB[:account_remember_keys].count.must_equal 0
    end

    it "should clear remember token when doing global logout in active_sessions_plugin" do
      rodauth do
        features = [:active_sessions, :remember]
        features.reverse! if before
        enable :login, *features
        hmac_secret '123'
      end
      roda do |r|
        r.rodauth
        rodauth.load_memory
        r.root{rodauth.logged_in? ? "Logged In" : "Not Logged In"}
      end

      login

      visit '/remember'
      choose 'Remember Me'
      click_button 'Change Remember Setting'
      DB[:account_remember_keys].count.must_equal 1

      visit '/logout'
      check 'global-logout'
      click_button 'Logout'
      DB[:account_remember_keys].count.must_equal 0
    end
  end

  it "should not use remember token if the account is not open" do
    rodauth do
      enable :login, :remember
      skip_status_checks? false
    end
    roda do |r|
      r.rodauth
      r.get 'load' do
        rodauth.load_memory
        r.redirect '/'
      end
      r.root do
        if rodauth.logged_in?
          if rodauth.logged_in_via_remember_key?
            "Logged In via Remember"
          else
            "Logged In Normally"
          end
        else
          "Not Logged In"
        end
      end
    end

    login
    page.body.must_equal 'Logged In Normally'

    visit '/load'
    page.body.must_equal 'Logged In Normally'

    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    page.body.must_equal 'Logged In Normally'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_equal 'Not Logged In'

    DB[:accounts].update(:status_id=>3)

    visit '/load'
    page.body.must_equal 'Not Logged In'
  end

  it "should handle uniqueness errors raised when inserting remember token" do
    rodauth do
      enable :login, :remember
    end
    roda do |r|
      def rodauth.raised_uniqueness_violation(*) super; true; end
      r.rodauth
      r.get 'load' do
        rodauth.load_memory
        r.redirect '/'
      end
      r.root do
        if rodauth.logged_in?
          if rodauth.logged_in_via_remember_key?
            "Logged In via Remember"
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
    page.body.must_equal 'Logged In Normally'
  end

  it "should handle uniqueness errors raised when inserting remember token without there being a valid row" do
    rodauth do
      enable :login, :remember
    end
    roda do |r|
      def rodauth.raised_uniqueness_violation(*) StandardError.new; end
      r.rodauth
      r.root{''}
    end

    login

    visit '/remember'
    choose 'Remember Me'
    proc{click_button 'Change Remember Setting'}.must_raise StandardError
  end

  [:jwt, :json].each do |json|
    it "should support login via remember token via #{json}" do
      rodauth do
        enable :login, :confirm_password, :remember
      end
      roda(json) do |r|
        r.rodauth

        r.post 'load' do
          rodauth.load_memory
          [4]
        end

        if rodauth.logged_in?
          if rodauth.logged_in_via_remember_key?
            [1]
          else
            [2]
          end
        else
          [3]
        end
      end

      json_request.must_equal [200, [3]]
      json_login
      json_request.must_equal [200, [2]]

      json_request('/load').must_equal [200, [4]]
      json_request.must_equal [200, [2]]

      res = json_request('/remember', :remember=>'remember')
      res.must_equal [200, {'success'=>"Your remember setting has been updated"}]

      @authorization = nil
      @cookie.delete("rack.session")
      json_request.must_equal [200, [3]]
      json_request('/load').must_equal [200, [4]]
      json_request.must_equal [200, [1]]

      remember_cookie = @cookie["_remember"]
      res = json_request('/remember', :remember=>'forget')
      res.must_equal [200, {'success'=>"Your remember setting has been updated"}]
      json_request.must_equal [200, [1]]

      @cookie = nil
      @authorization = nil
      json_request.must_equal [200, [3]]

      json_request('/load').must_equal [200, [4]]
      json_request.must_equal [200, [3]]

      @cookie = { "_remember" => remember_cookie }
      json_request('/load').must_equal [200, [4]]
      json_request.must_equal [200, [1]]

      res = json_request('/confirm-password', :password=>'123456')
      res.must_equal [401, {'reason'=>"invalid_password", 'error'=>"There was an error confirming your password", "field-error"=>["password", "invalid password"]}]

      res = json_request('/confirm-password', :password=>'0123456789')
      res.must_equal [200, {'success'=>"Your password has been confirmed"}]
      json_request.must_equal [200, [2]]

      res = json_request('/remember', :remember=>'disable')
      res.must_equal [200, {'success'=>"Your remember setting has been updated"}]

      @authorization = nil
      @cookie = nil
      json_request.must_equal [200, [3]]

      @cookie = { "_remember" => remember_cookie }
      json_request('/load').must_equal [200, [4]]
      json_request.must_equal [200, [3]]
    end
  end

  it "should support remember token management via internal requests" do
    key = nil
    rodauth do
      enable :login, :logout, :remember, :internal_request
      hmac_secret '123'
    end
    roda do |r|
      r.rodauth
      r.get 'setup' do
        key = rodauth.class.remember_setup(:account_login=>'foo@example.com')
        ::Rack::Utils.set_cookie_header!(response.headers, '_remember', :value=>key)
        ''
      end
      r.get 'load' do
        rodauth.load_memory
        r.redirect '/'
      end
      r.get 'loadpage' do
        rodauth.load_memory
        ''
      end
      r.root do
        if rodauth.logged_in?
          if rodauth.logged_in_via_remember_key?
            view :content=>"Logged In via Remember"
          else
            view :content=>"Logged In Normally"
          end
        else
          view :content=>"Not Logged In"
        end
      end
    end

    visit '/setup'
    page.body.must_equal ''

    app.rodauth.account_id_for_remember_key(:remember=>key).must_equal DB[:accounts].get(:id)

    proc do
      app.rodauth.account_id_for_remember_key(:remember=>key[0...-1])
    end.must_raise Rodauth::InternalRequestError

    visit '/'
    page.body.must_include 'Not Logged In'

    visit '/load'
    page.body.must_include 'Logged In via Remember'

    logout

    visit '/setup'
    page.body.must_equal ''

    app.rodauth.remember_disable(:account_login=>'foo@example.com').must_be_nil

    proc do
      app.rodauth.account_id_for_remember_key(:remember=>key)
    end.must_raise Rodauth::InternalRequestError

    visit '/load'
    page.body.must_include 'Not Logged In'
  end
end
