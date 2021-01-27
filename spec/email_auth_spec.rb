require_relative 'spec_helper'

describe 'Rodauth email auth feature' do
  it "should support logging in use link sent via email, without a password for the account" do
    rodauth do
      enable :login, :email_auth, :logout
      account_password_hash_column :ph
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>"Possible Authentication Methods-#{rodauth.possible_authentication_methods.join('/') if rodauth.logged_in?}"}
    end

    DB[:accounts].update(:ph=>nil).must_equal 1

    visit '/login'
    fill_in 'Login', :with=>'foo2@example.com'
    click_button 'Login'
    page.find('#error_flash').text.must_equal 'There was an error logging in'
    page.html.must_include("no matching login")

    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to login to your account"
    page.current_path.must_equal '/'
    link = email_link(/(\/email-auth\?key=.+)$/)

    proc{visit '/email-auth'}.must_raise RuntimeError

    visit link[0...-1]
    page.find('#error_flash').text.must_equal "There was an error logging you in: invalid email authentication key"

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    page.find('#error_flash').text.must_equal "An email has recently been sent to you with a link to login"
    Mail::TestMailer.deliveries.must_equal []

    DB[:account_email_auth_keys].update(:email_last_sent => Time.now - 250).must_equal 1
    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    page.find('#error_flash').text.must_equal "An email has recently been sent to you with a link to login"
    Mail::TestMailer.deliveries.must_equal []

    DB[:account_email_auth_keys].update(:email_last_sent => Time.now - 350).must_equal 1
    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    email_link(/(\/email-auth\?key=.+)$/).must_equal link

    visit link
    page.title.must_equal 'Login'
    click_button 'Login'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.current_path.must_equal '/'
    page.html.must_include 'Possible Authentication Methods-email_auth'

    logout

    visit link
    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'

    link2 = email_link(/(\/email-auth\?key=.+)$/)
    link2.wont_equal link

    visit link2
    DB[:account_email_auth_keys].update(:deadline => Time.now - 60).must_equal 1
    click_button 'Login'
    page.find('#error_flash').text.must_equal "There was an error logging you in"
    page.current_path.must_equal '/'
    DB[:account_email_auth_keys].count.must_equal 0

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'

    visit email_link(/(\/email-auth\?key=.+)$/)
    DB[:account_email_auth_keys].update(:key=>'1').must_equal 1
    click_button 'Login'
    page.find('#error_flash').text.must_equal "There was an error logging you in"
    page.current_path.must_equal '/'
  end

  it "should support logging in use link sent via email, with a password for the account" do
    rodauth do
      enable :login, :email_auth, :logout
      email_auth_email_last_sent_column nil
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>"Possible Authentication Methods-#{rodauth.possible_authentication_methods.join('/') if rodauth.logged_in?}"}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo2@example.com'
    click_button 'Login'
    page.find('#error_flash').text.must_equal 'There was an error logging in'
    page.html.must_include("no matching login")

    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    click_button 'Send Login Link Via Email'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to login to your account"
    page.current_path.must_equal '/'
    link = email_link(/(\/email-auth\?key=.+)$/)

    visit link[0...-1]
    page.find('#error_flash').text.must_equal "There was an error logging you in: invalid email authentication key"

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    click_button 'Send Login Link Via Email'
    email_link(/(\/email-auth\?key=.+)$/).must_equal link

    visit link
    page.title.must_equal 'Login'
    click_button 'Login'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.current_path.must_equal '/'
    page.html.must_include 'Possible Authentication Methods-password'

    logout

    visit link
    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    click_button 'Send Login Link Via Email'

    link2 = email_link(/(\/email-auth\?key=.+)$/)
    link2.wont_equal link

    visit link2
    DB[:account_email_auth_keys].update(:deadline => Time.now - 60).must_equal 1
    click_button 'Login'
    page.find('#error_flash').text.must_equal "There was an error logging you in"
    page.current_path.must_equal '/'
    DB[:account_email_auth_keys].count.must_equal 0

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    click_button 'Send Login Link Via Email'

    visit email_link(/(\/email-auth\?key=.+)$/)
    DB[:account_email_auth_keys].update(:key=>'1').must_equal 1
    click_button 'Login'
    page.find('#error_flash').text.must_equal "There was an error logging you in"
    page.current_path.must_equal '/'
  end

  it "should allow password login for accounts with password hashes" do
    rodauth do
      enable :login, :email_auth
    end
    roda do |r|
      r.rodauth
      next unless rodauth.logged_in?
      r.root{view :content=>"Logged In"}
    end

    visit '/login'
    page.title.must_equal 'Login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    page.html.must_include 'Send Login Link Via Email'

    fill_in 'Password', :with=>'012345678'
    click_button 'Login'
    page.find('#error_flash').text.must_equal "There was an error logging in"
    page.html.must_include("invalid password")
    page.html.must_include 'Send Login Link Via Email'

    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.current_path.must_equal '/'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
  end

  it "should work with creating accounts without setting passwords" do
    rodauth do
      enable :login, :create_account, :email_auth
      require_login_confirmation? false
      create_account_autologin? false
      create_account_set_password? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "Your account has been created"

    visit '/login'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Login'
    page.current_path.must_equal '/'
    visit email_link(/(\/email-auth\?key=.+)$/, 'foo@example2.com')
    page.title.must_equal 'Login'
    click_button 'Login'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.current_path.must_equal '/'
  end

  it "should allow returning to requested location when login was required" do
    rodauth do
      enable :login, :email_auth
      login_return_to_requested_location? true
      force_email_auth? true
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
      r.get('page') do
        rodauth.require_login
        view :content=>""
      end
    end

    visit "/page"
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    link = email_link(/(\/email-auth\?key=.+)$/)

    visit link
    click_button 'Login'
    page.current_path.must_equal "/page"
  end

  [true, false].each do |before|
    it "should clear email auth token when closing account, when loading email_auth #{before ? "before" : "after"}" do
      rodauth do
        features = [:close_account, :email_auth]
        features.reverse! if before
        enable :login, *features
      end
      roda do |r|
        r.rodauth
        r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
      end

      visit '/login'
      page.title.must_equal 'Login'
      fill_in 'Login', :with=>'foo@example.com'
      click_button 'Login'
      click_button 'Send Login Link Via Email'

      hash = DB[:account_email_auth_keys].first

      visit email_link(/(\/email-auth\?key=.+)$/)
      click_button 'Login'

      DB[:account_email_auth_keys].count.must_equal 0
      DB[:account_email_auth_keys].insert(hash)

      visit '/close-account'
      fill_in 'Password', :with=>'0123456789'
      click_button 'Close Account'
      DB[:account_email_auth_keys].count.must_equal 0
    end
  end

  it "should handle uniqueness errors raised when inserting email auth token" do
    rodauth do
      enable :login, :email_auth
    end
    roda do |r|
      def rodauth.raised_uniqueness_violation(*) super; true; end
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/login'
    page.title.must_equal 'Login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    click_button 'Send Login Link Via Email'
    link = email_link(/(\/email-auth\?key=.+)$/)

    DB[:account_email_auth_keys].update(:email_last_sent => Time.now - 350).must_equal 1
    visit '/login'
    page.title.must_equal 'Login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    click_button 'Send Login Link Via Email'
    email_link(/(\/email-auth\?key=.+)$/).must_equal link
  end

  it "should reraise uniqueness errors raised when inserting email auth token, when token not available" do
    rodauth do
      enable :login, :email_auth
    end
    roda do |r|
      def rodauth.raised_uniqueness_violation(*) StandardError.new; end
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/login'
    page.title.must_equal 'Login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    proc{click_button 'Send Login Link Via Email'}.must_raise StandardError
  end

  [:jwt, :json].each do |json|
    it "should support email auth for accounts via #{json}" do
      rodauth do
        enable :login, :email_auth
        email_auth_email_body{email_auth_email_link}
      end
      roda(json) do |r|
        r.rodauth
      end

      res = json_request('/email-auth-request')
      res.must_equal [401, {"error"=>"There was an error requesting an email link to authenticate"}]

      res = json_request('/email-auth-request', :login=>'foo@example2.com')
      res.must_equal [401, {"error"=>"There was an error requesting an email link to authenticate"}]

      res = json_request('/email-auth-request', :login=>'foo@example.com')
      res.must_equal [200, {"success"=>"An email has been sent to you with a link to login to your account"}]

      link = email_link(/key=.+$/)
      res = json_request('/email-auth')
      res.must_equal [401, {"error"=>"There was an error logging you in"}]

      res = json_request('/email-auth', :key=>link[4...-1])
      res.must_equal [401, {"error"=>"There was an error logging you in"}]

      res = json_request('/email-auth', :key=>link[4..-1])
      res.must_equal [200, {"success"=>"You have been logged in"}]
    end
  end
end

