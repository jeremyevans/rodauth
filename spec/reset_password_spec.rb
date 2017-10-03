require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth reset_password feature' do
  it "should support resetting passwords for accounts" do
    rodauth do
      enable :login, :reset_password
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    login(:login=>'foo@example2.com', :pass=>'01234567')
    page.html.wont_match(/notice_flash/)

    login(:pass=>'01234567', :visit=>false)

    click_button 'Request Password Reset'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to reset the password for your account"
    page.current_path.must_equal '/'
    link = email_link(/(\/reset-password\?key=.+)$/)

    visit link[0...-1]
    page.find('#error_flash').text.must_equal "invalid password reset key"

    visit '/login'
    click_link 'Forgot Password?'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Request Password Reset'
    email_link(/(\/reset-password\?key=.+)$/).must_equal link

    visit '/login'
    login(:pass=>'01234567', :visit=>false)
    click_button 'Request Password Reset'
    email_link(/(\/reset-password\?key=.+)$/).must_equal link

    visit link
    page.title.must_equal 'Reset Password'

    fill_in 'Password', :with=>'0123456'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Reset Password'
    page.html.must_include("passwords do not match")
    page.find('#error_flash').text.must_equal "There was an error resetting your password"
    page.current_path.must_equal '/reset-password'

    fill_in 'Password', :with=>'0123456789'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Reset Password'
    page.body.must_include 'invalid password, same as current password'
    page.find('#error_flash').text.must_equal "There was an error resetting your password"
    page.current_path.must_equal '/reset-password'

    fill_in 'Password', :with=>'012'
    fill_in 'Confirm Password', :with=>'012'
    click_button 'Reset Password'
    page.html.must_include("invalid password, does not meet requirements")
    page.find('#error_flash').text.must_equal "There was an error resetting your password"
    page.current_path.must_equal '/reset-password'

    fill_in 'Password', :with=>'0123456'
    fill_in 'Confirm Password', :with=>'0123456'
    click_button 'Reset Password'
    page.find('#notice_flash').text.must_equal "Your password has been reset"
    page.current_path.must_equal '/'

    login(:pass=>'0123456')
    page.current_path.must_equal '/'

    login(:pass=>'bad')
    click_link "Forgot Password?"
    fill_in "Login", :with=>"foo@example.com"
    click_button "Request Password Reset"
    DB[:account_password_reset_keys].update(:deadline => Time.now - 60).must_equal 1
    link = email_link(/(\/reset-password\?key=.+)$/)
    visit link
    page.find('#error_flash').text.must_equal "invalid password reset key"
  end

  it "should support resetting passwords for accounts without confirmation" do
    rodauth do
      enable :login, :reset_password
      require_password_confirmation? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/login'
    login(:pass=>'01234567', :visit=>false)
    click_button 'Request Password Reset'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to reset the password for your account"

    link = email_link(/(\/reset-password\?key=.+)$/)
    visit link
    fill_in 'Password', :with=>'0123456'
    click_button 'Reset Password'
    page.find('#notice_flash').text.must_equal "Your password has been reset"
  end

  it "should support autologin when resetting passwords for accounts" do
    rodauth do
      enable :login, :reset_password
      reset_password_autologin? true
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
    end

    login(:pass=>'01234567')

    click_button 'Request Password Reset'
    link = email_link(/(\/reset-password\?key=.+)$/)
    visit link
    fill_in 'Password', :with=>'0123456'
    fill_in 'Confirm Password', :with=>'0123456'
    click_button 'Reset Password'
    page.find('#notice_flash').text.must_equal "Your password has been reset"
    page.body.must_include("Logged In")
  end

  it "should clear reset password token when closing account" do
    rodauth do
      enable :login, :reset_password, :close_account
      reset_password_autologin? true
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
    end

    login(:pass=>'01234567')
    click_button 'Request Password Reset'
    email_link(/(\/reset-password\?key=.+)$/)

    login

    DB[:account_password_reset_keys].count.must_equal 1
    visit '/close-account'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Close Account'
    DB[:account_password_reset_keys].count.must_equal 0
  end

  it "should handle uniqueness errors raised when inserting password reset token" do
    rodauth do
      enable :login, :reset_password
    end
    roda do |r|
      def rodauth.raised_uniqueness_violation(*) super; true; end
      r.rodauth
      r.root{view :content=>""}
    end

    login(:pass=>'01234567')

    click_button 'Request Password Reset'
    link = email_link(/(\/reset-password\?key=.+)$/)
    visit link

    fill_in 'Password', :with=>'0123456'
    fill_in 'Confirm Password', :with=>'0123456'
    click_button 'Reset Password'
    page.find('#notice_flash').text.must_equal "Your password has been reset"
  end

  it "should support resetting passwords for accounts via jwt" do
    rodauth do
      enable :login, :reset_password
      reset_password_email_body{reset_password_email_link}
    end
    roda(:jwt) do |r|
      r.rodauth
    end

    res = json_login(:pass=>'1', :no_check=>true)
    res.must_equal [401, {"field-error"=>["password", "invalid password"], "error"=>"There was an error logging in"}]

    res = json_request('/reset-password')
    res.must_equal [401, {"error"=>"There was an error resetting your password"}]

    res = json_request('/reset-password-request', :login=>'foo@example2.com')
    res.must_equal [401, {"error"=>"There was an error requesting a password reset"}]

    res = json_request('/reset-password-request', :login=>'foo@example.com')
    res.must_equal [200, {"success"=>"An email has been sent to you with a link to reset the password for your account"}]

    link = email_link(/key=.+$/)
    res = json_request('/reset-password', :key=>link[4...-1])
    res.must_equal [401, {"error"=>"There was an error resetting your password"}]

    res = json_request('/reset-password', :key=>link[4..-1], :password=>'1', "password-confirm"=>'2')
    res.must_equal [422, {"error"=>"There was an error resetting your password", "field-error"=>["password", 'passwords do not match']}]

    res = json_request('/reset-password', :key=>link[4..-1], :password=>'0123456789', "password-confirm"=>'0123456789')
    res.must_equal [422, {"error"=>"There was an error resetting your password", "field-error"=>["password", 'invalid password, same as current password']}]

    res = json_request('/reset-password', :key=>link[4..-1], :password=>'1', "password-confirm"=>'1')
    res.must_equal [422, {"error"=>"There was an error resetting your password", "field-error"=>["password", "invalid password, does not meet requirements (minimum 6 characters)"]}]

    res = json_request('/reset-password', :key=>link[4..-1], :password=>"\0ab123456", "password-confirm"=>"\0ab123456")
    res.must_equal [422, {"error"=>"There was an error resetting your password", "field-error"=>["password", "invalid password, does not meet requirements (contains null byte)"]}]

    res = json_request('/reset-password', :key=>link[4..-1], :password=>'0123456', "password-confirm"=>'0123456')
    res.must_equal [200, {"success"=>"Your password has been reset"}]

    json_login(:pass=>'0123456')
  end
end
