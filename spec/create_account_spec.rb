require_relative 'spec_helper'

describe 'Rodauth create_account feature' do
  [false, true].each do |ph|
    it "should support creating accounts #{'with account_password_hash_column' if ph}" do
      rodauth do
        enable :login, :create_account
        account_password_hash_column :ph if ph
        create_account_autologin? false
      end
      roda do |r|
        r.rodauth
        r.root{view :content=>""}
      end

      visit '/create-account'
      page.find_by_id('password')[:autocomplete].must_equal 'new-password'

      fill_in 'Login', :with=>'foo@example.com'
      fill_in 'Confirm Login', :with=>'foo@example.com'
      fill_in 'Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'0123456789'
      click_button 'Create Account'
      page.html.must_include("invalid login, already an account with this login")
      page.find('#error_flash').text.must_equal "There was an error creating your account"
      page.current_path.must_equal '/create-account'

      fill_in 'Login', :with=>'foobar'
      fill_in 'Confirm Login', :with=>'foobar'
      fill_in 'Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'0123456789'
      click_button 'Create Account'
      page.html.must_include("invalid login, not a valid email address")
      page.find('#error_flash').text.must_equal "There was an error creating your account"
      page.current_path.must_equal '/create-account'

      fill_in 'Login', :with=>'foo@example2.com'
      fill_in 'Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'0123456789'
      click_button 'Create Account'
      page.html.must_include("logins do not match")
      page.find('#error_flash').text.must_equal "There was an error creating your account"
      page.current_path.must_equal '/create-account'

      fill_in 'Confirm Login', :with=>'foo@example2.com'
      fill_in 'Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'012345678'
      click_button 'Create Account'
      page.html.must_include("passwords do not match")
      page.find('#error_flash').text.must_equal "There was an error creating your account"
      page.current_path.must_equal '/create-account'

      fill_in 'Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'0123456789'
      click_button 'Create Account'
      page.find('#notice_flash').text.must_equal "Your account has been created"
      page.current_path.must_equal '/'

      login(:login=>'foo@example2.com')
      page.current_path.must_equal '/'
    end
  end

  it "should support creating accounts without login/password confirmation" do
    rodauth do
      enable :login, :create_account
      require_login_confirmation? false
      require_password_confirmation? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>"Autologin-#{rodauth.autologin_type}"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "Your account has been created"
    page.html.must_include 'Autologin-create_account'
  end

  it "should support autologin after account creation" do
    rodauth do
      enable :create_account
    end
    roda do |r|
      r.rodauth
      next unless rodauth.logged_in?
      r.root{view :content=>"Logged In: #{DB[:accounts].where(:id=>rodauth.session_value).get(:email)}"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo2@example.com'
    fill_in 'Confirm Login', :with=>'foo2@example.com'
    fill_in 'Password', :with=>'apple2'
    fill_in 'Confirm Password', :with=>'apple2'
    click_button 'Create Account'
    page.html.must_include("Logged In: foo2@example.com")
  end

  [:jwt, :json].each do |json|
    it "should support creating accounts via #{json}" do
      rodauth do
        enable :login, :create_account
        after_create_account{json_response[:account_id] = account_id}
        create_account_autologin? false
      end
      roda(json) do |r|
        r.rodauth
      end

      res = json_request('/create-account', :login=>'foo@example.com', "login-confirm"=>'foo@example.com', :password=>'0123456789', "password-confirm"=>'0123456789')
      res.must_equal [422, {'reason'=>"already_an_account_with_this_login",'error'=>"There was an error creating your account", "field-error"=>["login", "invalid login, already an account with this login"]}]
            
      res = json_request('/create-account', :login=>'f', "login-confirm"=>'f', :password=>'0123456789', "password-confirm"=>'0123456789')
      res.must_equal [422, {'reason'=>"login_too_short",'error'=>"There was an error creating your account", "field-error"=>["login", "invalid login, minimum 3 characters"]}]
      
      res = json_request('/create-account', :login=>'f'*256, "login-confirm"=>'f'*256, :password=>'0123456789', "password-confirm"=>'0123456789')
      res.must_equal [422, {'reason'=>"login_too_long",'error'=>"There was an error creating your account", "field-error"=>["login", "invalid login, maximum 255 characters"]}]

      res = json_request('/create-account', :login=>'foobar', "login-confirm"=>'foobar', :password=>'0123456789', "password-confirm"=>'0123456789')
      res.must_equal [422, {'reason'=>"login_not_valid_email",'error'=>"There was an error creating your account", "field-error"=>["login", "invalid login, not a valid email address"]}]

      res = json_request('/create-account', :login=>'foo@example2.com', "login-confirm"=>'foobar', :password=>'0123456789', "password-confirm"=>'0123456789')
      res.must_equal [422, {'reason'=>"logins_do_not_match",'error'=>"There was an error creating your account", "field-error"=>["login", "logins do not match"]}]

      res = json_request('/create-account', :login=>'foo@example2.com', "login-confirm"=>'foo@example2.com', :password=>'012345678', "password-confirm"=>'0123456789')
      res.must_equal [422, {'reason'=>"passwords_do_not_match",'error'=>"There was an error creating your account", "field-error"=>["password", "passwords do not match"]}]

      res = json_request('/create-account', :login=>'foo@example2.com', "login-confirm"=>'foo@example2.com', :password=>'0123456789', "password-confirm"=>'0123456789')
      res.must_equal [200, {'success'=>"Your account has been created", 'account_id'=>DB[:accounts].where(:email=>'foo@example2.com').get(:id)}]

      json_login(:login=>'foo@example2.com')
    end
  end

  it "should support creating accounts using an internal request" do
    rodauth do
      enable :login, :create_account, :internal_request
    end
    roda do |r|
      r.rodauth
      r.root{rodauth.logged_in?.nil?.to_s}
    end

    proc do
      app.rodauth.create_account(:login=>'foo', :password=>'sdkjnlsalkklsda')
    end.must_raise Rodauth::InternalRequestError

    proc do
      app.rodauth.create_account(:login=>'foo3@example.com', :password=>'123')
    end.must_raise Rodauth::InternalRequestError

    app.rodauth.create_account(:login=>'foo3@example.com', :password=>'sdkjnlsalkklsda').must_be_nil

    login(:login=>'foo3@example.com', :pass=>'sdkjnlsalkklsda')
    page.current_path.must_equal '/'
    page.body.must_equal 'false'
  end
end
