require File.expand_path("spec_helper", File.dirname(__FILE__))

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
      create_account_autologin? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "Your account has been created"
  end

  it "should support autologin after account creation" do
    rodauth do
      enable :create_account
    end
    roda do |r|
      r.rodauth
      next unless session[:account_id]
      r.root{view :content=>"Logged In: #{DB[:accounts].where(:id=>session[:account_id]).get(:email)}"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo2@example.com'
    fill_in 'Confirm Login', :with=>'foo2@example.com'
    fill_in 'Password', :with=>'apple2'
    fill_in 'Confirm Password', :with=>'apple2'
    click_button 'Create Account'
    page.html.must_include("Logged In: foo2@example.com")
  end

  it "should support creating accounts via jwt" do
    rodauth do
      enable :login, :create_account
      after_create_account{json_response[:account_id] = account_id}
      create_account_autologin? false
    end
    roda(:jwt) do |r|
      r.rodauth
    end

    res = json_request('/create-account', :login=>'foo@example.com', "login-confirm"=>'foo@example.com', :password=>'0123456789', "password-confirm"=>'0123456789')
    res.must_equal [422, {'error'=>"There was an error creating your account", "field-error"=>["login", "invalid login, already an account with this login"]}]

    res = json_request('/create-account', :login=>'foobar', "login-confirm"=>'foobar', :password=>'0123456789', "password-confirm"=>'0123456789')
    res.must_equal [422, {'error'=>"There was an error creating your account", "field-error"=>["login", "invalid login, not a valid email address"]}]

    res = json_request('/create-account', :login=>'foo@example2.com', "login-confirm"=>'foobar', :password=>'0123456789', "password-confirm"=>'0123456789')
    res.must_equal [422, {'error'=>"There was an error creating your account", "field-error"=>["login", "logins do not match"]}]

    res = json_request('/create-account', :login=>'foo@example2.com', "login-confirm"=>'foo@example2.com', :password=>'012345678', "password-confirm"=>'0123456789')
    res.must_equal [422, {'error'=>"There was an error creating your account", "field-error"=>["password", "passwords do not match"]}]

    res = json_request('/create-account', :login=>'foo@example2.com', "login-confirm"=>'foo@example2.com', :password=>'0123456789', "password-confirm"=>'0123456789')
    res.must_equal [200, {'success'=>"Your account has been created", 'account_id'=>DB[:accounts].max(:id)}]

    json_login(:login=>'foo@example2.com')
  end
end
