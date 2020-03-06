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
    page.find('#error_flash').text.must_equal "This session has expired, please login again."

    login
    page.title.must_equal 'Login'
    page.find('#error_flash').text.must_equal "This session has expired, please login again."

    inactivity = 10
    login
    page.body.must_include "Logged In"

    visit '/set-creation'
    page.title.must_equal 'Login'
    page.find('#error_flash').text.must_equal "This session has expired, please login again."

    login
    page.body.must_include "Logged In"

    visit '/remove-creation'
    page.title.must_equal 'Login'
    page.find('#error_flash').text.must_equal "This session has expired, please login again."

    expiration_default = false
    login
    page.body.must_include "Logged In"

    visit '/remove-creation'
    page.body.must_include "Logged In"
  end
end
