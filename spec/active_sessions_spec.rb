require_relative 'spec_helper'

describe 'Rodauth active sessions feature' do
  [true, false].each do |before|
    it "should check that session is active, when loading active_sessions #{before ? "before" : "after"}" do
      rodauth do
        features = [:logout, :active_sessions]
        features.reverse! if before
        enable :login, *features
        hmac_secret '123'
      end
      roda do |r|
        r.is("precheck"){rodauth.currently_active_session? ? "Active" : "Inactive"}
        rodauth.check_active_session
        r.rodauth
        r.is("clear"){rodauth.clear_session; r.redirect '/'}
        r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
      end

      visit '/precheck'
      page.body.must_equal "Inactive"

      login
      page.body.must_include "Logged In"

      visit '/precheck'
      page.body.must_equal "Active"

      session1 = get_cookie('rack.session')

      logout

      visit '/'
      page.body.must_include "Not Logged"

      remove_cookie('rack.session')
      set_cookie('rack.session', session1)
      visit '/foo'
      page.current_path.must_equal '/'
      page.body.must_include "Not Logged"
      page.find('#error_flash').text.must_equal "This session has been logged out"

      login
      page.body.must_include "Logged In"

      session2 = get_cookie('rack.session')
      remove_cookie('rack.session')
      set_cookie('rack.session', session1)
      visit '/'
      page.body.must_include "Not Logged"
      page.find('#error_flash').text.must_equal "This session has been logged out"

      remove_cookie('rack.session')
      set_cookie('rack.session', session2)
      visit '/'
      page.body.must_include "Logged In"

      visit '/clear'
      page.current_path.must_equal '/'
      page.body.must_include "Not Logged"

      set_cookie('rack.session', session2)
      visit '/'
      page.body.must_include "Logged In"

      DB[:account_active_session_keys].delete
      visit '/precheck'
      page.body.must_equal "Inactive"

      visit '/'
      page.body.must_include "Not Logged"
    end
  end

  it "should remove previous active session when updating session" do
    rodauth do
      enable :create_account, :verify_account_grace_period, :active_sessions
      create_account_autologin? true
      verify_account_autologin? true
      hmac_secret '123'
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit "/create-account"
    fill_in "Login", with: "foo@example2.com"
    fill_in "Password", with: "secret"
    fill_in "Confirm Password", with: "secret"
    click_on "Create Account"
    DB[:account_active_session_keys].count.must_equal 1

    visit email_link(/(\/verify-account\?key=.+)$/, "foo@example2.com")
    click_on "Verify Account"
    DB[:account_active_session_keys].count.must_equal 1
  end

  it "should handle session inactivity and lifetime deadlines" do
    session_inactivity_deadline = 86400
    session_lifetime_deadline = 86400*30
    rodauth do
      enable :login, :logout, :active_sessions
      hmac_secret '123'
      session_inactivity_deadline{session_inactivity_deadline}
      session_lifetime_deadline{session_lifetime_deadline}
    end
    roda do |r|
      rodauth.check_active_session
      r.rodauth
      r.is("clear"){rodauth.clear_session; r.redirect '/'}
      r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
    end

    login
    page.body.must_include "Logged In"

    DB[:account_active_session_keys].update(:last_use=>Time.now - 86400/2)
    visit '/'
    page.body.must_include "Logged In"

    DB[:account_active_session_keys].update(:last_use=>Time.now - 86400*2)
    visit '/'
    page.body.must_include "Not Logged"

    login

    DB[:account_active_session_keys].update(:created_at=>Time.now - 86400*29)
    visit '/'
    page.body.must_include "Logged In"

    DB[:account_active_session_keys].update(:created_at=>Time.now - 86400*31)
    visit '/'
    page.body.must_include "Not Logged"

    session_inactivity_deadline = 50
    login

    DB[:account_active_session_keys].update(:last_use=>Time.now - 25)
    visit '/'
    page.body.must_include "Logged In"

    DB[:account_active_session_keys].update(:last_use=>Time.now - 75)
    visit '/'
    page.body.must_include "Not Logged"

    session_lifetime_deadline = 100
    login

    DB[:account_active_session_keys].update(:created_at=>Time.now - 50)
    visit '/'
    page.body.must_include "Logged In"

    DB[:account_active_session_keys].update(:created_at=>Time.now - 150)
    visit '/'
    page.body.must_include "Not Logged"

    session_inactivity_deadline = 50
    session_lifetime_deadline = nil
    login

    DB[:account_active_session_keys].update(:last_use=>Time.now - 25)
    visit '/'
    page.body.must_include "Logged In"

    DB[:account_active_session_keys].update(:last_use=>Time.now - 75)
    visit '/'
    page.body.must_include "Not Logged"

    session_inactivity_deadline = nil
    session_lifetime_deadline = 100
    login

    DB[:account_active_session_keys].update(:created_at=>Time.now - 50)
    visit '/'
    page.body.must_include "Logged In"

    DB[:account_active_session_keys].update(:created_at=>Time.now - 150)
    visit '/'
    page.body.must_include "Not Logged"

    session_inactivity_deadline = 10
    session_lifetime_deadline = 100
    login

    DB[:account_active_session_keys].update(:last_use=>Time.now - 5, :created_at=>Time.now - 50)
    visit '/'
    page.body.must_include "Logged In"

    DB[:account_active_session_keys].update(:last_use=>Time.now - 15, :created_at=>Time.now - 150)
    visit '/'
    page.body.must_include "Not Logged"

    session_inactivity_deadline = nil
    session_lifetime_deadline = nil
    login

    DB[:account_active_session_keys].update(:last_use=>Time.now - 5, :created_at=>Time.now - 50)
    visit '/'
    page.body.must_include "Logged In"

    DB[:account_active_session_keys].update(:last_use=>Time.now - 86400, :created_at=>Time.now - 150)
    visit '/'
    page.body.must_include "Logged In"
    t = DB[:account_active_session_keys].get(:last_use)
    t = Time.parse(t) if t.is_a?(String)
    t.must_be(:<, Time.now - 10)
  end

  it "should logout inactive session when using remember" do
    rodauth do
      enable :login, :active_sessions, :remember
      hmac_secret '123'
      after_login { remember_login }
    end
    roda do |r|
      rodauth.check_active_session
      rodauth.load_memory
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
    end

    login
    DB[:account_active_session_keys].delete

    visit '/'
    page.body.must_include "Not Logged"
  end

  it "should logout all sessions for account on logout if that option is selected" do
    rodauth do
      enable :login, :active_sessions
      hmac_secret '123'
    end
    roda do |r|
      rodauth.check_active_session
      r.rodauth
      r.is("clear"){rodauth.clear_session; r.redirect '/'}
      rodauth.session[rodauth.session_id_session_key] || ''
    end

    login
    session_id1 = page.body
    session1 = get_cookie('rack.session')

    visit '/clear'

    login
    session_id2 = page.body
    session2 = get_cookie('rack.session')

    session_id1.wont_equal session_id2

    remove_cookie('rack.session')
    set_cookie('rack.session', session1)
    visit '/'
    page.body.must_equal session_id1

    remove_cookie('rack.session')
    set_cookie('rack.session', session2)
    visit '/'
    page.body.must_equal session_id2

    visit '/logout'
    check 'Logout all Logged In Sessions?'
    click_button 'Logout'

    remove_cookie('rack.session')
    set_cookie('rack.session', session1)
    visit '/'
    page.body.must_equal ''

    remove_cookie('rack.session')
    set_cookie('rack.session', session2)
    visit '/'
    page.body.must_equal ''
  end

  it "should handle duplicate session ids by sharing them by default" do
    random_key = nil
    rodauth do
      enable :login, :active_sessions
      hmac_secret '123'
      random_key{random_key ||= super()}
    end
    roda do |r|
      rodauth.check_active_session
      r.rodauth
      r.is("clear"){rodauth.clear_session; r.redirect '/'}
      rodauth.session[rodauth.session_id_session_key] || ''
    end

    login
    session_id1 = page.body
    session1 = get_cookie('rack.session')

    visit '/clear'

    login
    session_id2 = page.body
    session2 = get_cookie('rack.session')

    session_id1.must_equal session_id2

    remove_cookie('rack.session')
    set_cookie('rack.session', session1)
    visit '/'
    page.body.must_equal session_id1

    remove_cookie('rack.session')
    set_cookie('rack.session', session2)
    visit '/'
    page.body.must_equal session_id2

    visit '/logout'
    click_button 'Logout'

    remove_cookie('rack.session')
    set_cookie('rack.session', session1)
    visit '/'
    page.body.must_equal ''

    remove_cookie('rack.session')
    set_cookie('rack.session', session2)
    visit '/'
    page.body.must_equal ''
  end

  [true, false].each do |before|
    it "should remove active session keys when closing accounts, when active_sessions is loaded #{before ? "before" : "after"}" do
      rodauth do
        features = [:close_account, :active_sessions]
        features.reverse! if before
        enable :login, *features
        close_account_requires_password? false
        hmac_secret '123'
      end
      roda do |r|
        rodauth.check_active_session
        r.rodauth
        r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
      end

      login

      DB[:account_active_session_keys].count.must_equal 1
      visit '/close-account'
      click_button 'Close Account'
      DB[:account_active_session_keys].count.must_equal 0
    end
  end

  it "should handle cases where active session id is not set during logout, to handle cases where active_sessions was added after session creation" do
    rodauth do
      enable :login, :active_sessions
      hmac_secret '123'
    end
    roda do |r|
      r.rodauth
      rodauth.check_active_session
      r.get('remove_session_id'){session.delete(rodauth.session_id_session_key); r.redirect '/logout'}
      r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
    end

    login

    visit '/remove_session_id'
    click_button 'Logout'
    page.title.must_equal 'Login'
  end

  it "should limit accounts to a single logged in session when using jwt" do
    rodauth do
      enable :login, :active_sessions
      hmac_secret '123'
    end
    roda(:jwt) do |r|
      rodauth.check_active_session
      r.rodauth
      r.post("clear"){rodauth.clear_session; [3]}
      rodauth.logged_in? ? [1] : [2]
    end

    json_login
    authorization1 = @authorization
    json_logout

    json_request.must_equal [200, [2]]
    @authorization = authorization1
    json_request.must_equal [401, {'reason'=>'inactive_session', 'error'=>"This session has been logged out"}]

    json_login
    json_request.must_equal [200, [1]]

    authorization2 = @authorization
    @authorization = authorization1
    json_request.must_equal [401, {'reason'=>'inactive_session', 'error'=>"This session has been logged out"}]

    @authorization = authorization2
    json_request.must_equal [200, [1]]

    json_request('/clear').must_equal [200, [3]]

    json_login
    authorization3 = @authorization
    json_request.must_equal [200, [1]]

    @authorization = authorization2
    json_request.must_equal [200, [1]]

    res = json_request("/logout", 'global_logout'=>'t')
    res.must_equal [200, {"success"=>'You have been logged out'}]

    @authorization = authorization2
    json_request.must_equal [401, {'reason'=>'inactive_session', 'error'=>"This session has been logged out"}]
    json_request.must_equal [200, [2]]

    @authorization = authorization3
    json_request.must_equal [401, {'reason'=>'inactive_session', 'error'=>"This session has been logged out"}]
    json_request.must_equal [200, [2]]
  end
end
