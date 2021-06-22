require_relative 'spec_helper'

describe 'Rodauth change_login feature' do
  it "should support changing logins for accounts" do
    DB[:accounts].insert(:email=>'foo2@example.com')
    require_password = false
    require_email = true

    rodauth do
      enable :login, :logout, :change_login
      change_login_requires_password?{require_password}
      require_email_address_logins?{require_email}
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    login
    page.current_path.must_equal '/'

    visit '/change-login'
    page.title.must_equal 'Change Login'

    fill_in 'Login', :with=>'foobar'
    fill_in 'Confirm Login', :with=>'foobar'
    click_button 'Change Login'
    page.find('#error_flash').text.must_equal "There was an error changing your login"
    page.html.must_include("invalid login, not a valid email address")
    page.current_path.must_equal '/change-login'

    require_email = false

    fill_in 'Login', :with=>'fb'
    fill_in 'Confirm Login', :with=>'fb'
    click_button 'Change Login'
    page.find('#error_flash').text.must_equal "There was an error changing your login"
    page.html.must_include("invalid login, minimum 3 characters")
    page.current_path.must_equal '/change-login'

    fill_in 'Login', :with=>'f'*256
    fill_in 'Confirm Login', :with=>'f'*256
    click_button 'Change Login'
    page.find('#error_flash').text.must_equal "There was an error changing your login"
    page.html.must_include("invalid login, maximum 255 characters")
    page.current_path.must_equal '/change-login'

    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Confirm Login', :with=>'foo2@example.com'
    click_button 'Change Login'
    page.find('#error_flash').text.must_equal "There was an error changing your login"
    page.html.must_include("logins do not match")
    page.current_path.must_equal '/change-login'

    fill_in 'Login', :with=>'foo2@example.com'
    click_button 'Change Login'
    page.find('#error_flash').text.must_equal "There was an error changing your login"
    page.html.must_include("invalid login, already an account with this login")
    page.current_path.must_equal '/change-login'

    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Confirm Login', :with=>'foo@example.com'
    click_button 'Change Login'
    page.find('#error_flash').text.must_equal "There was an error changing your login"
    page.html.must_include("invalid login, same as current login")
    page.current_path.must_equal '/change-login'

    fill_in 'Login', :with=>'foo3@example.com'
    fill_in 'Confirm Login', :with=>'foo3@example.com'
    click_button 'Change Login'
    page.find('#notice_flash').text.must_equal "Your login has been changed"
    page.current_path.must_equal '/'

    logout
    login(:login=>'foo3@example.com')
    page.current_path.must_equal '/'

    require_password = true
    visit '/change-login'
    fill_in 'Password', :with=>'012345678'
    fill_in 'Login', :with=>'foo4@example.com'
    fill_in 'Confirm Login', :with=>'foo4@example.com'
    click_button 'Change Login'
    page.find('#error_flash').text.must_equal "There was an error changing your login"
    page.html.must_include("invalid password")
    page.current_path.must_equal '/change-login'

    fill_in 'Password', :with=>'0123456789'
    click_button 'Change Login'
    page.find('#notice_flash').text.must_equal "Your login has been changed"
    page.current_path.must_equal '/'

    logout
    login(:login=>'foo4@example.com')
    page.current_path.must_equal '/'
  end

  it "should support changing logins for accounts without login confirmation" do
    rodauth do
      enable :login, :change_login
      change_login_requires_password? false
      require_login_confirmation? false
      login_meets_requirements?{|login| login.length > 4}
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    login

    visit '/change-login'
    fill_in 'Login', :with=>'foo'
    click_button 'Change Login'
    page.html.must_include "invalid login"
    page.html.wont_include "invalid login,"

    visit '/change-login'
    fill_in 'Login', :with=>'foo3@example.com'
    click_button 'Change Login'
    page.find('#notice_flash').text.must_equal "Your login has been changed"
  end

  [:jwt, :json].each do |json|
    it "should support changing logins via #{json}" do
      DB[:accounts].insert(:email=>'foo2@example.com')
      require_password = false

      rodauth do
        enable :login, :logout, :change_login
        change_login_requires_password?{require_password}
      end
      roda(json) do |r|
        r.rodauth
      end

      json_login

      res = json_request('/change-login', :login=>'foobar', "login-confirm"=>'foobar')
      res.must_equal [422, {'reason'=>"login_not_valid_email",'error'=>"There was an error changing your login", "field-error"=>["login", "invalid login, not a valid email address"]}]

      res = json_request('/change-login', :login=>'foo@example.com', "login-confirm"=>'foo2@example.com')
      res.must_equal [422, {'reason'=>"logins_do_not_match",'error'=>"There was an error changing your login", "field-error"=>["login", "logins do not match"]}]

      res = json_request('/change-login', :login=>'foo2@example.com', "login-confirm"=>'foo2@example.com')
      res.must_equal [422, {'reason'=>"already_an_account_with_this_login",'error'=>"There was an error changing your login", "field-error"=>["login", "invalid login, already an account with this login"]}]
    
      res = json_request('/change-login', :login=>'f', "login-confirm"=>'f')
      res.must_equal [422, {'reason'=>"login_too_short",'error'=>"There was an error changing your login", "field-error"=>["login", "invalid login, minimum 3 characters"]}]
      
      res = json_request('/change-login', :login=>'f'*256, "login-confirm"=>'f'*256)
      res.must_equal [422, {'reason'=>"login_too_long",'error'=>"There was an error changing your login", "field-error"=>["login", "invalid login, maximum 255 characters"]}]

      res = json_request('/change-login', :login=>'foo3@example.com', "login-confirm"=>'foo3@example.com')
      res.must_equal [200, {'success'=>"Your login has been changed"}]

      json_logout
      json_login(:login=>'foo3@example.com')

      require_password = true

      res = json_request('/change-login', :login=>'foo4@example.com', "login-confirm"=>'foo4@example.com', :password=>'012345678')
      res.must_equal [401, {'reason'=>"invalid_password",'error'=>"There was an error changing your login", "field-error"=>["password", "invalid password"]}]

      res = json_request('/change-login', :login=>'foo4@example.com', "login-confirm"=>'foo4@example.com', :password=>'0123456789')
      res.must_equal [200, {'success'=>"Your login has been changed"}]

      json_logout
      json_login(:login=>'foo4@example.com')
    end
  end

  it "should support changing logins using an internal request" do
    rodauth do
      enable :login, :change_login, :internal_request
      login_meets_requirements?{|login| login.length > 4}
    end
    roda do |r|
      r.rodauth
      r.root{rodauth.logged_in?.nil?.to_s}
    end

    proc do
      app.rodauth.change_login(:account_login=>'foo@example.com', :login=>'foo')
    end.must_raise Rodauth::InternalRequestError

    app.rodauth.change_login(:account_login=>'foo@example.com', :login=>'foo3@example.com').must_be_nil

    visit '/'
    page.body.must_equal 'true'

    login
    page.current_path.must_equal '/login'

    login(:login=>'foo3@example.com', :visit=>false)
    page.current_path.must_equal '/'
    page.body.must_equal 'false'
  end
end
