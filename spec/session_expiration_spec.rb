require_relative 'spec_helper'

describe 'Rodauth session expiration feature' do
  it "should expire sessions based on last activity and max lifetime checks" do
    inactivity = max_lifetime = 300
    expiration_default = true
    rodauth do
      enable :login, :session_expiration
      session_expiration_default{expiration_default}
      session_inactivity_timeout{inactivity}
      max_session_lifetime{max_lifetime}
    end
    roda do |r|
      rodauth.check_session_expiration
      r.rodauth
      r.get("remove-creation"){session.delete(rodauth.session_created_session_key); r.redirect '/'}
      r.get("set-lastact"){session[rodauth.session_last_activity_session_key] = Time.now.to_i - 100000; r.redirect '/'}
      r.get("set-creation"){session[rodauth.session_created_session_key] = Time.now.to_i - 100000; r.redirect '/'}
      r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
    end

    visit '/'
    page.body.must_include "Not Logged"

    login
    page.body.must_include "Logged In"

    inactivity = -1
    visit '/'
    page.title.must_equal 'Login'
    page.find('#error_flash').text.must_equal "This session has expired, please login again"
    login
    page.title.must_equal 'Login'
    page.find('#error_flash').text.must_equal "This session has expired, please login again"

    inactivity = 10
    login
    max_lifetime = -1
    visit '/'
    page.find('#error_flash').text.must_equal "This session has expired, please login again"
    login
    page.title.must_equal 'Login'
    page.find('#error_flash').text.must_equal "This session has expired, please login again"

    max_lifetime = 10
    login
    page.body.must_include "Logged In"

    visit '/set-creation'
    page.title.must_equal 'Login'
    page.find('#error_flash').text.must_equal "This session has expired, please login again"

    login
    page.body.must_include "Logged In"

    visit '/remove-creation'
    page.title.must_equal 'Login'
    page.find('#error_flash').text.must_equal "This session has expired, please login again"

    expiration_default = false
    login
    page.body.must_include "Logged In"

    visit '/remove-creation'
    page.body.must_include "Logged In"
  end

  it "should expire sessions based on last activity and max lifetime checks when using jwt" do
    inactivity = max_lifetime = 300
    expiration_default = true
    rodauth do
      enable :login, :logout, :session_expiration
      session_expiration_default{expiration_default}
      session_inactivity_timeout{inactivity}
      max_session_lifetime{max_lifetime}
    end
    roda(:jwt) do |r|
      rodauth.check_session_expiration
      r.rodauth
      r.post("set-creation"){rodauth.send(:set_session_value, rodauth.session_created_session_key, Time.now.to_i - 100000); [5]}
      r.post("remove-creation"){rodauth.send(:remove_session_value, rodauth.session_created_session_key); [4]}
      rodauth.logged_in? ? [1] : [2]
    end

    json_request.must_equal [200, [2]]

    json_login
    json_request.must_equal [200, [1]]

    inactivity = -1
    json_request.must_equal [401, {'reason'=>'session_expired', 'error'=>"This session has expired, please login again"}]
    json_login
    json_request.must_equal [401, {'reason'=>'session_expired', 'error'=>"This session has expired, please login again"}]

    inactivity = 10
    json_login
    max_lifetime = -1
    json_request.must_equal [401, {'reason'=>'session_expired', 'error'=>"This session has expired, please login again"}]
    json_login
    json_request.must_equal [401, {'reason'=>'session_expired', 'error'=>"This session has expired, please login again"}]

    max_lifetime = 10
    json_login
    json_request.must_equal [200, [1]]
    json_request('/set-creation').must_equal [200, [5]]
    json_request.must_equal [401, {'reason'=>'session_expired', 'error'=>"This session has expired, please login again"}]

    json_login
    json_request.must_equal [200, [1]]
    json_request('/remove-creation').must_equal [200, [4]]
    json_request.must_equal [401, {'reason'=>'session_expired', 'error'=>"This session has expired, please login again"}]

    expiration_default = false
    json_login
    json_request.must_equal [200, [1]]
    json_request('/remove-creation').must_equal [200, [4]]
    json_request.must_equal [200, [1]]
  end
end
