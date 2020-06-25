require_relative 'spec_helper'

describe 'Rodauth single session feature' do
  [true, false].each do |before|
    it "should limit accounts to a single logged in session, when loading single_session #{before ? "before" : "after"}" do
      secret = nil
      allow_raw = true
      rodauth do
        features = [:logout, :single_session]
        features.reverse! if before
        enable :login, *features
        hmac_secret{secret}
        allow_raw_single_session_key?{allow_raw}
      end
      roda do |r|
        rodauth.check_single_session
        r.rodauth
        r.is("reset"){rodauth.reset_single_session_key; r.redirect '/'}
        r.is("clear"){session.delete(rodauth.single_session_session_key); DB[:account_session_keys].delete; r.redirect '/'}
        r.is("cleardb"){DB[:account_session_keys].delete; r.redirect '/'}
        r.is("clearsession"){session.delete(rodauth.single_session_session_key); r.redirect '/'}
        r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
      end

      visit '/reset'
      page.body.must_include "Not Logged"

      login
      page.body.must_include "Logged In"

      session1 = get_cookie('rack.session')

      logout

      visit '/'
      page.body.must_include "Not Logged"

      remove_cookie('rack.session')
      set_cookie('rack.session', session1)
      visit '/foo'
      page.current_path.must_equal '/'
      page.body.must_include "Not Logged"
      page.find('#error_flash').text.must_equal "This session has been logged out as another session has become active"

      login
      page.body.must_include "Logged In"

      session2 = get_cookie('rack.session')
      remove_cookie('rack.session')
      set_cookie('rack.session', session1)
      visit '/'
      page.body.must_include "Not Logged"
      page.find('#error_flash').text.must_equal "This session has been logged out as another session has become active"

      remove_cookie('rack.session')
      set_cookie('rack.session', session2)
      visit '/'
      page.body.must_include "Logged In"

      visit '/clear'
      page.current_path.must_equal '/'
      page.body.must_include "Logged In"

      secret = SecureRandom.random_bytes(32)
      visit '/'
      page.body.must_include "Logged In"

      allow_raw = false
      visit '/'
      page.body.must_include "Not Logged"

      login
      page.body.must_include "Logged In"

      visit '/clearsession'
      page.body.must_include "Logged In"

      visit '/cleardb'
      page.body.must_include "Logged In"

      login
      page.body.must_include "Logged In"

      visit '/reset'
      page.body.must_include "Not Logged"

      login
      page.body.must_include "Logged In"

      allow_raw = true
      secret = SecureRandom.random_bytes(32)
      visit '/'
      page.body.must_include "Not Logged"
    end

    it "should remove single session keys when closing accounts, when loading single_session #{before ? "before" : "after"}" do
      rodauth do
        features = [:close_account, :single_session]
        features.reverse! if before
        enable :login, *features
        close_account_requires_password? false
      end
      roda do |r|
        rodauth.check_single_session
        r.rodauth
        r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
      end

      login

      DB[:account_session_keys].count.must_equal 1
      visit '/close-account'
      click_button 'Close Account'
      DB[:account_session_keys].count.must_equal 0
    end
  end

  it "should limit accounts to a single logged in session when using jwt" do
    rodauth do
      enable :login, :logout, :single_session
    end
    roda(:jwt) do |r|
      rodauth.check_single_session
      r.rodauth
      r.post("clear"){rodauth.session.delete(:single_session_key); DB[:account_session_keys].delete; [3]}
      rodauth.logged_in? ? [1] : [2]
    end

    json_login
    authorization1 = @authorization
    json_logout

    json_request.must_equal [200, [2]]
    @authorization = authorization1
    json_request.must_equal [401, {'error'=>"This session has been logged out as another session has become active"}]

    json_login
    json_request.must_equal [200, [1]]

    authorization2 = @authorization
    @authorization = authorization1
    json_request.must_equal [401, {'error'=>"This session has been logged out as another session has become active"}]

    @authorization = authorization2
    json_request.must_equal [200, [1]]

    json_request('/clear').must_equal [200, [3]]
    json_request.must_equal [401, {'error'=>"This session has been logged out as another session has become active"}]
    json_request.must_equal [200, [2]]

    @authorization = authorization2
    json_request.must_equal [401, {'error'=>"This session has been logged out as another session has become active"}]
  end
end
