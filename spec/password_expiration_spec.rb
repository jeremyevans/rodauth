require_relative 'spec_helper'

describe 'Rodauth password expiration feature' do
  it "should force password changes after x number of days" do
    rodauth do
      enable :login, :logout, :change_password, :reset_password, :password_expiration
      allow_password_change_after 1000
      change_password_requires_password? false
    end
    roda do |r|
      r.rodauth
      rodauth.require_current_password if rodauth.logged_in?
      r.root{view :content=>""}
    end

    login(:pass=>'01234567')
    click_button 'Request Password Reset'
    link = email_link(/(\/reset-password\?key=.+)$/)

    visit link[0...-1]
    page.find('#error_flash').text.must_equal "There was an error resetting your password: invalid or expired password reset key"

    visit link
    page.current_path.must_equal '/reset-password'

    login
    page.current_path.must_equal '/'

    visit '/change-password'
    fill_in 'New Password', :with=>'banana'
    fill_in 'Confirm Password', :with=>'banana'
    click_button 'Change Password'
    page.current_path.must_equal '/'

    visit '/change-password'
    page.current_path.must_equal '/'
    page.find('#error_flash').text.must_equal "Your password cannot be changed yet"

    logout

    visit link
    page.current_path.must_equal '/'
    page.find('#error_flash').text.must_equal "Your password cannot be changed yet"

    DB[:account_password_change_times].update(:changed_at=>Time.now - 1100)

    visit link
    page.current_path.must_equal '/reset-password'

    login(:pass=>'banana')
    page.current_path.must_equal '/'

    visit '/change-password'
    page.current_path.must_equal '/change-password'

    logout

    DB[:account_password_change_times].update(:changed_at=>Time.now - 91*86400)

    login(:pass=>'banana')
    page.current_path.must_equal '/change-password'
    page.find('#error_flash').text.must_equal "Your password has expired and needs to be changed"

    visit '/foo'
    page.current_path.must_equal '/change-password'
    page.find('#error_flash').text.must_equal "Your password has expired and needs to be changed"

    fill_in 'New Password', :with=>'banana2'
    fill_in 'Confirm Password', :with=>'banana2'
    click_button 'Change Password'
    page.current_path.must_equal '/'

    visit '/change-password'
    page.current_path.must_equal '/'
    page.find('#error_flash').text.must_equal "Your password cannot be changed yet"

    logout

    visit link
    page.current_path.must_equal '/'
    page.find('#error_flash').text.must_equal "Your password cannot be changed yet"
  end

  it "should update password changed at when creating accounts" do
    rodauth do
      enable :login, :change_password, :password_expiration
      password_expiration_default true
      change_password_requires_password? false
    end
    roda do |r|
      r.rodauth
      rodauth.require_current_password
      r.root{view :content=>""}
    end

    login
    page.current_path.must_equal '/change-password'

    visit '/'
    page.current_path.must_equal '/change-password'
    fill_in 'New Password', :with=>'banana'
    fill_in 'Confirm Password', :with=>'banana'
    click_button 'Change Password'
    page.current_path.must_equal '/'
  end

  it "should update password changed at when creating accounts" do
    rodauth do
      enable :login, :create_account, :password_expiration
      allow_password_change_after 1000
      account_password_hash_column :ph
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo2@example.com'
    fill_in 'Confirm Login', :with=>'foo2@example.com'
    fill_in 'Password', :with=>'apple2'
    fill_in 'Confirm Password', :with=>'apple2'
    click_button 'Create Account'

    visit '/change-password'
    page.current_path.must_equal '/'
    page.find('#error_flash').text.must_equal "Your password cannot be changed yet"
  end

  [true, false].each do |before|
    it "should remove password expiration data when closing accounts, when loading password_expiration #{before ? "before" : "after"}" do
      rodauth do
        features = [:create_account, :close_account, :password_expiration]
        features.reverse! if before
        enable :login, *features
        close_account_requires_password? false
        create_account_autologin? true
      end
      roda do |r|
        r.rodauth
        r.root{view :content=>""}
      end

      visit '/create-account'
      fill_in 'Login', :with=>'foo2@example.com'
      fill_in 'Confirm Login', :with=>'foo2@example.com'
      fill_in 'Password', :with=>'apple2'
      fill_in 'Confirm Password', :with=>'apple2'
      click_button 'Create Account'

      DB[:account_password_change_times].count.must_equal 1
      visit '/close-account'
      click_button 'Close Account'
      DB[:account_password_change_times].count.must_equal 0
    end
  end

  it "should handle the case where the password is expired while the user has logged in" do
    rodauth do
      enable :login, :change_password, :password_expiration
      password_expiration_default true
      allow_password_change_after(-1000)
      change_password_requires_password? false
      require_password_change_after 3600
    end
    roda do |r|
      r.rodauth
      rodauth.require_current_password
      r.get("expire", :d){|d| session[:password_changed_at] = Time.now.to_i - d.to_i; r.redirect '/'}
      r.root{view :content=>""}
    end

    login
    page.current_path.must_equal '/change-password'

    visit '/'
    page.current_path.must_equal '/change-password'
    fill_in 'New Password', :with=>'banana'
    fill_in 'Confirm Password', :with=>'banana'
    click_button 'Change Password'
    page.current_path.must_equal '/'

    visit "/expire/90"
    page.current_path.must_equal '/'

    visit "/expire/7200"
    page.current_path.must_equal '/change-password'
  end

  it "should force password changes via jwt" do
    rodauth do
      enable :login, :logout, :change_password, :reset_password, :password_expiration
      allow_password_change_after 1000
      change_password_requires_password? false
      reset_password_email_body{reset_password_email_link}
    end
    roda(:jwt) do |r|
      r.rodauth
      rodauth.require_current_password
      if rodauth.authenticated?
        [1]
      else
        [2]
      end
    end

    json_request.must_equal [200, [2]]

    res = json_request('/reset-password-request', :login=>'foo@example.com')
    res.must_equal [200, {"success"=>"An email has been sent to you with a link to reset the password for your account"}]
    link = email_link(/key=.+$/)

    json_login

    res = json_request('/change-password', :password=>'0123456789', "new-password"=>'0123456', "password-confirm"=>'0123456')
    res.must_equal [200, {'success'=>"Your password has been changed"}]

    json_request.must_equal [200, [1]]

    res = json_request('/change-password', :password=>'0123456', "new-password"=>'01234567', "password-confirm"=>'01234567')
    res.must_equal [400, {'error'=>"Your password cannot be changed yet"}]

    json_logout

    res = json_request('/reset-password', :key=>link[4..-1], :password=>'01234567', "password-confirm"=>'01234567')
    res.must_equal [400, {'error'=>"Your password cannot be changed yet"}]

    DB[:account_password_change_times].update(:changed_at=>Time.now - 1100)
    res = json_request('/reset-password', :key=>link[4..-1], :password=>'01234567', "password-confirm"=>'01234567')
    res.must_equal [200, {"success"=>"Your password has been reset"}]

    DB[:account_password_change_times].update(:changed_at=>Time.now - 1100)
    json_login(:pass=>'01234567')
    res = json_request('/change-password', :password=>'01234567', "new-password"=>'012345678', "password-confirm"=>'012345678')
    res.must_equal [200, {'success'=>"Your password has been changed"}]

    DB[:account_password_change_times].update(:changed_at=>Time.now - 91*86400)

    json_logout
    json_request.must_equal [200, [2]]

    res = json_login(:pass=>'012345678', :no_check=>true)
    res.must_equal [400, {'error'=>"Your password has expired and needs to be changed"}]
    json_request.must_equal [400, {'error'=>"Your password has expired and needs to be changed"}]

    res = json_request('/change-password', :password=>'012345678', "new-password"=>'012345678a', "password-confirm"=>'012345678a')
    res.must_equal [200, {'success'=>"Your password has been changed"}]

    json_request.must_equal [200, [1]]
  end
end
