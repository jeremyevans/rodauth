require_relative 'spec_helper'

describe 'Rodauth change_password feature' do
  [false, true].each do |ph|
    it "should support changing passwords for accounts #{'with account_password_hash_column' if ph}" do
      require_password = true
      rodauth do
        enable :login, :logout, :change_password
        account_password_hash_column :ph if ph
        change_password_requires_password?{require_password}
      end
      roda do |r|
        r.rodauth
        r.root{view :content=>""}
      end

      login
      page.current_path.must_equal '/'

      visit '/change-password'
      page.title.must_equal 'Change Password'

      fill_in 'Password', :with=>'0123456789'
      fill_in 'New Password', :with=>'0123456'
      fill_in 'Confirm Password', :with=>'0123456789'
      click_button 'Change Password'
      page.html.must_include("passwords do not match")
      page.find('#error_flash').text.must_equal "There was an error changing your password"
      page.current_path.must_equal '/change-password'

      fill_in 'Password', :with=>'0123456'
      fill_in 'New Password', :with=>'0123456'
      fill_in 'Confirm Password', :with=>'0123456'
      click_button 'Change Password'
      page.find('#error_flash').text.must_equal "There was an error changing your password"
      page.body.must_include 'invalid password'
      page.current_path.must_equal '/change-password'

      fill_in 'Password', :with=>'0123456789'
      fill_in 'New Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'0123456789'
      click_button 'Change Password'
      page.find('#error_flash').text.must_equal "There was an error changing your password"
      page.body.must_include 'invalid password, same as current password'
      page.current_path.must_equal '/change-password'

      fill_in 'Password', :with=>'0123456789'
      fill_in 'New Password', :with=>'0123456'
      fill_in 'Confirm Password', :with=>'0123456'
      click_button 'Change Password'
      page.find('#notice_flash').text.must_equal "Your password has been changed"
      page.current_path.must_equal '/'

      logout
      login
      page.html.must_include("invalid password")
      page.current_path.must_equal '/login'

      fill_in 'Password', :with=>'0123456'
      click_button 'Login'
      page.current_path.must_equal '/'

      require_password = false
      visit '/change-password'
      fill_in 'New Password', :with=>'012345678'
      fill_in 'Confirm Password', :with=>'012345678'
      click_button 'Change Password'
      page.find('#notice_flash').text.must_equal "Your password has been changed"
      page.current_path.must_equal '/'

      login(:pass=>'012345678')
      page.current_path.must_equal '/'
    end
  end

  it "should support changing passwords for accounts without confirmation" do
    rodauth do
      enable :login, :change_password
      modifications_require_password? false
      require_password_confirmation? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    login
    visit '/change-password'
    fill_in 'New Password', :with=>'012345678'
    click_button 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"
  end

  it "should support invalid_previous_password_message" do
    rodauth do
      enable :login, :logout, :change_password
      invalid_previous_password_message "Previous password not correct"
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    login
    page.current_path.must_equal '/'

    visit '/change-password'
    page.title.must_equal 'Change Password'

    fill_in 'Password', :with=>'0123456'
    fill_in 'New Password', :with=>'0123456'
    fill_in 'Confirm Password', :with=>'0123456'
    click_button 'Change Password'
    page.find('#error_flash').text.must_equal "There was an error changing your password"
    page.body.must_include 'Previous password not correct'
    page.current_path.must_equal '/change-password'
  end

  it "should support setting requirements for passwords" do
    rodauth do
      enable :login, :create_account, :change_password
      create_account_autologin? false
      password_meets_requirements? do |password|
        password =~ /banana/
      end
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo2@example.com'
    fill_in 'Confirm Login', :with=>'foo2@example.com'
    fill_in 'Password', :with=>'apple'
    fill_in 'Confirm Password', :with=>'apple'
    click_button 'Create Account'
    page.html.must_include("invalid password, does not meet requirements")
    page.find('#error_flash').text.must_equal "There was an error creating your account"
    page.current_path.must_equal '/create-account'

    fill_in 'Password', :with=>'banana'
    fill_in 'Confirm Password', :with=>'banana'
    click_button 'Create Account'

    login(:login=>'foo2@example.com', :pass=>'banana')

    visit '/change-password'
    fill_in 'Password', :with=>'banana'
    fill_in 'New Password', :with=>'apple'
    fill_in 'Confirm Password', :with=>'apple'
    click_button 'Change Password'
    page.html.must_include("invalid password, does not meet requirements")
    page.find('#error_flash').text.must_equal "There was an error changing your password"
    page.current_path.must_equal '/change-password'

    fill_in 'Password', :with=>'banana'
    fill_in 'New Password', :with=>'my_banana_3'
    fill_in 'Confirm Password', :with=>'my_banana_3'
    click_button 'Change Password'
    page.current_path.must_equal '/'
  end

  [:jwt, :json].each do |json|
    it "should support changing passwords for accounts via #{json}" do
      require_password = true
      rodauth do
        enable :login, :logout, :change_password
        change_password_requires_password?{require_password}
      end
      roda(json) do |r|
        r.rodauth
      end

      json_login

      res = json_request('/change-password', :password=>'0123456789', "new-password"=>'0123456', "password-confirm"=>'0123456789')
      res.must_equal [422, {'reason'=>"passwords_do_not_match",'error'=>"There was an error changing your password", "field-error"=>["new-password", "passwords do not match"]}]

      res = json_request('/change-password', :password=>'0123456', "new-password"=>'0123456', "password-confirm"=>'0123456')
      res.must_equal [401, {'reason'=>"invalid_previous_password",'error'=>"There was an error changing your password", "field-error"=>["password", "invalid password"]}]

      res = json_request('/change-password', :password=>'0123456789', "new-password"=>'0123456789', "password-confirm"=>'0123456789')
      res.must_equal [422, {'reason'=>"same_as_existing_password",'error'=>"There was an error changing your password", "field-error"=>["new-password", "invalid password, same as current password"]}]

      res = json_request('/change-password', :password=>'0123456789', "new-password"=>'0123456', "password-confirm"=>'0123456')
      res.must_equal [200, {'success'=>"Your password has been changed"}]

      json_logout
      res = json_login(:no_check=>true)
      res.must_equal [401, {'reason'=>"invalid_password",'error'=>"There was an error logging in", "field-error"=>["password", "invalid password"]}]

      json_login(:pass=>'0123456')

      require_password = false

      res = json_request('/change-password', "new-password"=>'012345678', "password-confirm"=>'012345678')
      res.must_equal [200, {'success'=>"Your password has been changed"}]

      json_logout
      json_login(:pass=>'012345678')
    end
  end

  it "should support changing passwords using an internal request" do
    rodauth do
      enable :login, :logout, :change_password, :internal_request
    end
    roda do |r|
      r.rodauth
      r.root{rodauth.logged_in?.nil?.to_s}
    end

    proc do
      app.rodauth.change_password(:account_login=>'foo@example.com', :new_password=>'foo')
    end.must_raise Rodauth::InternalRequestError

    proc do
      app.rodauth.change_password(:account_login=>'foo@example.com', :password=>'foo')
    end.must_raise Rodauth::InternalRequestError

    app.rodauth.change_password(:account_login=>'foo@example.com', :new_password=>'0123456').must_be_nil

    visit '/'
    page.body.must_equal 'true'

    login
    page.current_path.must_equal '/login'

    login(:pass=>'0123456')
    page.current_path.must_equal '/'
    page.body.must_equal 'false'
    logout

    app.rodauth.change_password(:account_login=>'foo@example.com', :password=>'01234567').must_be_nil

    login(:pass=>'01234567')
    page.current_path.must_equal '/'
    page.body.must_equal 'false'
  end
end
