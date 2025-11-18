require_relative 'spec_helper'

describe 'Rodauth confirm password feature' do
  [true, false].each do |before|
    it "should support confirming passwords, when loading confirm_password #{before ? "before" : "after"}" do
      rodauth do
        features = [:password_grace_period, :confirm_password]
        features.reverse! if before
        enable :login, :change_login, *features
        before_change_login_route do
          unless password_recently_entered?
            set_session_value(confirm_password_redirect_session_key, request.path_info)
            redirect '/confirm-password'
          end
        end
      end
      roda do |r|
        r.rodauth
        r.get("a"){rodauth.require_password_authentication; view(:content=>"authed")}
        r.get("from_remember"){rodauth.authenticated_by.replace ["remember"]; ""}
        r.get("reset") do
          session[rodauth.last_password_entry_session_key] = Time.now.to_i - 400
          "a"
        end
        view :content=>""
      end

      login

      visit '/change-login'
      page.title.must_equal 'Change Login'

      visit '/reset'
      page.body.must_equal 'a'

      visit "/a"
      page.title.must_equal 'Confirm Password'

      visit '/change-login'
      page.title.must_equal 'Confirm Password'
      fill_in 'Password', :with=>'012345678'
      click_button 'Confirm Password'
      page.find('#error_flash').text.must_equal "There was an error confirming your password"
      page.html.must_include("invalid password")

      fill_in 'Password', :with=>'0123456789'
      click_button 'Confirm Password'
      page.find('#notice_flash').text.must_equal "Your password has been confirmed"

      visit "/a"
      page.body.must_include "authed"

      visit "/from_remember"
      visit "/a"
      page.title.must_equal 'Confirm Password'

      fill_in 'Password', :with=>'0123456789'
      click_button 'Confirm Password'
      page.find('#notice_flash').text.must_equal "Your password has been confirmed"

      visit '/change-login'
      visit '/change-login'
      fill_in 'Login', :with=>'foo3@example.com'
      fill_in 'Confirm Login', :with=>'foo3@example.com'
      click_button 'Change Login'
      page.find('#notice_flash').text.must_equal "Your login has been changed"
    end
  end

  it "should support confirming passwords for accounts using email auth" do
    rodauth do
      enable :login, :email_auth, :confirm_password
      email_auth_email_last_sent_column nil
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>(rodauth.authenticated_by ? "Authenticated via #{rodauth.authenticated_by.join(' and ')}" : '')}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Login'
    click_button 'Send Login Link Via Email'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to login to your account"
    page.current_path.must_equal '/'
    link = email_link(/(\/email-auth\?key=.+)$/)

    visit link
    click_button 'Login'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.current_path.must_equal '/'
    page.html.must_include "Authenticated via email_auth"

    visit '/confirm-password'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Confirm Password'
    page.current_path.must_equal '/'
    page.html.must_include "Authenticated via password"
  end

  it "should allow requiring password confirmation" do
    rodauth do
      enable :login, :confirm_password, :password_grace_period
      login_return_to_requested_location? true
    end
    roda do |r|
      r.rodauth
      r.get("reset") do
        session[rodauth.last_password_entry_session_key] = Time.now.to_i - 400
        "a"
      end
      r.get("page") do
        rodauth.require_password_authentication
        view :content=>"Password Authentication Passed: #{r.params['foo']}"
      end
      view :content=>""
    end

    visit '/page?foo=bar'
    page.current_path.must_equal '/login'

    login(:visit=>false)
    page.body.must_include "Password Authentication Passed: bar"
    page.find('#notice_flash').text.must_equal "You have been logged in"

    visit '/reset'
    page.body.must_equal 'a'

    visit '/page?foo=bar'
    page.current_path.must_equal '/confirm-password'
    page.find('#error_flash').text.must_equal "You need to confirm your password before continuing"

    fill_in 'Password', :with=>'0123456789'
    click_button 'Confirm Password'
    page.find('#notice_flash').text.must_equal "Your password has been confirmed"
    page.body.must_include "Password Authentication Passed: bar"
  end

  it "should not display confirm password link on login page if route is disabled" do
    route = "confirm-password"
    rodauth do
      enable :login, :confirm_password, :email_auth, :recovery_codes
      confirm_password_route { route }
      auto_add_recovery_codes? true
      after_login { auto_add_missing_recovery_codes }
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>"Home"}
    end

    visit '/login'
    fill_in 'Login', with: 'foo@example.com'
    click_button 'Login'
    click_button 'Send Login Link Via Email'
    link = email_link(/(\/email-auth\?key=.+)$/)

    visit link
    click_button 'Login'

    visit '/multifactor-auth'
    click_on 'Enter Password'
    page.current_path.must_equal '/confirm-password'

    route = nil
    visit '/multifactor-auth'
    page.current_path.must_equal '/recovery-auth'
  end

  [:jwt, :json].each do |json|
    it "should support confirming passwords via #{json}" do
      rodauth do
        enable :password_grace_period, :login, :change_password, :confirm_password
      end
      roda(json) do |r|
        r.rodauth
        response[CONTENT_TYPE_KEY] = 'application/json'
        r.post("reset"){rodauth.send(:set_session_value, rodauth.last_password_entry_session_key, Time.now.to_i - 400); [1]}
        r.post("page") do
          rodauth.require_password_authentication
          '1'
        end
      end

      json_login

      json_request('/reset').must_equal [200, [1]]

      res = json_request('/page')
      res.must_equal [401, {'reason'=>'password_authentication_required', 'error'=>"You need to confirm your password before continuing"}]

      res = json_request('/confirm-password', :password=>'0123456789')
      res.must_equal [200, {'success'=>"Your password has been confirmed"}]

      res = json_request('/page')
      res.must_equal [200, 1]

      res = json_request('/change-password', "new-password"=>'0123456', "password-confirm"=>'0123456')
      res.must_equal [200, {'success'=>"Your password has been changed"}]

      json_request('/reset').must_equal [200, [1]]

      res = json_request('/change-password', "new-password"=>'01234567', "password-confirm"=>'01234567')
      res.must_equal [401, {'reason'=>"invalid_previous_password","field-error"=>["password", "invalid password"], "error"=>"There was an error changing your password"}]

      res = json_request('/confirm-password', "password"=>'0123456')
      res.must_equal [200, {'success'=>"Your password has been confirmed"}]

      res = json_request('/change-password', "new-password"=>'01234567', "password-confirm"=>'01234567')
      res.must_equal [200, {'success'=>"Your password has been changed"}]
    end
  end
end
