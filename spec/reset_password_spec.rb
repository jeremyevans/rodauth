require_relative 'spec_helper'

describe 'Rodauth reset_password feature' do
  [:no_hmac, :hmac, :hmac_raw].each do |hmac_type|
    it "should support resetting passwords for accounts, for #{hmac_type}" do
      last_sent_column = nil
      rodauth do
        enable :login, :reset_password
        case hmac_type
        when :hmac
          hmac_secret '1'
        when :hmac_raw
          hmac_secret '1'
          allow_raw_email_token? true
        end
        reset_password_email_last_sent_column{last_sent_column}
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

      proc{visit '/reset-password'}.must_raise RuntimeError

      visit link[0...-1]
      page.find('#error_flash').text.must_equal "There was an error resetting your password: invalid or expired password reset key"

      visit '/login'
      click_link 'Forgot Password?'
      page.current_path.must_equal '/reset-password-request'

      fill_in 'Login', :with=>'foo@example2.com'
      click_button 'Request Password Reset'
      page.find('#error_flash').text.must_equal "There was an error requesting a password reset"
      page.current_path.must_equal '/reset-password-request'
      page.html.must_include("no matching login")
      page.all('[type=email]').first.value.must_equal 'foo@example2.com'

      fill_in 'Login', :with=>'foo@example.com'
      click_button 'Request Password Reset'
      email_link(/(\/reset-password\?key=.+)$/).must_equal link

      login(:pass=>'01234567')
      click_button 'Request Password Reset'
      email_link(/(\/reset-password\?key=.+)$/).must_equal link

      last_sent_column = :email_last_sent
      login(:pass=>'01234567')
      click_button 'Request Password Reset'
      page.find('#error_flash').text.must_equal "An email has recently been sent to you with a link to reset your password"
      Mail::TestMailer.deliveries.must_equal []

      DB[:account_password_reset_keys].update(:email_last_sent => Time.now - 250).must_equal 1
      login(:pass=>'01234567')
      click_button 'Request Password Reset'
      page.find('#error_flash').text.must_equal "An email has recently been sent to you with a link to reset your password"
      Mail::TestMailer.deliveries.must_equal []

      DB[:account_password_reset_keys].update(:email_last_sent => Time.now - 350).must_equal 1
      login(:pass=>'01234567')
      click_button 'Request Password Reset'
      email_link(/(\/reset-password\?key=.+)$/).must_equal link

      visit link
      page.title.must_equal 'Reset Password'
      page.find_by_id('password')[:autocomplete].must_equal 'new-password'

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
      page.find('#error_flash').text.must_equal "There was an error resetting your password: invalid or expired password reset key"
    end
  end

  [true, false].each do |convert|
    it "should support resetting passwords for accounts without confirmation#{' when not converting token ids to integer'}" do
      rodauth do
        enable :login, :reset_password
        require_password_confirmation? false
        account_id_column{super() if scope} unless convert
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

  it "should not allow password reset for unverified account" do
    rodauth do
      enable :reset_password
      skip_status_checks? false
      require_mail? false
    end
    roda do |r|
      r.rodauth
      next unless rodauth.logged_in?
      r.root{view :content=>""}
    end

    DB[:accounts].update(:status_id=>1)

    visit '/reset-password-request'
    fill_in 'Login', :with=>'foo@example.com'
    click_button 'Request Password Reset'
    page.find('#error_flash').text.must_equal "There was an error requesting a password reset"
    page.html.must_include("unverified account, please verify account before logging in")
    page.current_path.must_equal '/reset-password-request'
  end

  [true, false].each do |before|
    it "should clear reset password token when closing account, when loading reset_password #{before ? "before" : "after"}" do
      rodauth do
        features = [:close_account, :reset_password]
        features.reverse! if before
        enable :login, *features
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

  it "should reraise uniqueness errors raised when inserting password reset token when token doesn't exist" do
    rodauth do
      enable :login, :reset_password
    end
    roda do |r|
      def rodauth.raised_uniqueness_violation(*) StandardError.new; end
      r.rodauth
      r.root{view :content=>""}
    end

    login(:pass=>'01234567')
    proc{click_button 'Request Password Reset'}.must_raise StandardError
  end

  it "should not display reset password request link on login page if route is disabled" do
    route = 'reset-password-request'
    rodauth do
      enable :login, :reset_password
      reset_password_request_route { route }
    end
    roda do |r|
      r.rodauth
    end

    visit '/login'
    click_on 'Forgot Password?'
    page.current_path.must_equal '/reset-password-request'

    route = nil
    visit '/login'
    page.html.wont_include "Forgot Password?"
  end

  [:jwt, :json].each do |json|
    it "should support resetting passwords for accounts via #{json}" do
      rodauth do
        enable :login, :reset_password
        reset_password_email_body{reset_password_email_link}
        null_byte_parameter_value{|_, v| v}
      end
      roda(json) do |r|
        r.rodauth
      end

      res = json_login(:pass=>'1', :no_check=>true)
      res.must_equal [401, {'reason'=>"invalid_password","field-error"=>["password", "invalid password"], "error"=>"There was an error logging in"}]

      res = json_request('/reset-password')
      res.must_equal [401, {"reason"=>"invalid_reset_password_key", "error"=>"There was an error resetting your password"}]

      res = json_request('/reset-password-request', :login=>'foo@example2.com')
      res.must_equal [401, {'reason'=>"no_matching_login","field-error"=>["login", "no matching login"], "error"=>"There was an error requesting a password reset"}]

      res = json_request('/reset-password-request', :login=>'foo@example.com')
      res.must_equal [200, {"success"=>"An email has been sent to you with a link to reset the password for your account"}]

      link = email_link(/key=.+$/)
      res = json_request('/reset-password', :key=>link[4...-1])
      res.must_equal [401, {"reason"=>"invalid_reset_password_key", "error"=>"There was an error resetting your password"}]

      res = json_request('/reset-password', :key=>link[4..-1], :password=>'ab1234561', "password-confirm"=>'ab1234562')
      res.must_equal [422, {'reason'=>"passwords_do_not_match","error"=>"There was an error resetting your password", "field-error"=>["password", 'passwords do not match']}]

      res = json_request('/reset-password', :key=>link[4..-1], :password=>'0123456789', "password-confirm"=>'0123456789')
      res.must_equal [422, {'reason'=>"same_as_existing_password","error"=>"There was an error resetting your password", "field-error"=>["password", 'invalid password, same as current password']}]

      res = json_request('/reset-password', :key=>link[4..-1], :password=>'1', "password-confirm"=>'1')
      res.must_equal [422, {'reason'=>"password_too_short","error"=>"There was an error resetting your password", "field-error"=>["password", "invalid password, does not meet requirements (minimum 6 characters)"]}]

      res = json_request('/reset-password', :key=>link[4..-1], :password=>"\0ab123456", "password-confirm"=>"\0ab123456")
      res.must_equal [422, {'reason'=>"password_contains_null_byte","error"=>"There was an error resetting your password", "field-error"=>["password", "invalid password, does not meet requirements (contains null byte)"]}]

      res = json_request('/reset-password', :key=>link[4..-1], :password=>'0123456', "password-confirm"=>'0123456')
      res.must_equal [200, {"success"=>"Your password has been reset"}]

      json_login(:pass=>'0123456')
    end
  end

  it "should support requesting password resets using an internal request" do
    rodauth do
      enable :login, :logout, :reset_password, :internal_request
      reset_password_email_last_sent_column nil
      domain 'example.com'
      internal_request_configuration do
        csrf_tag { |*| fail "must not rely on Roda session" }
      end
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>(rodauth.logged_in? ? "Logged In" : "Not Logged")}
    end

    proc do
      app.rodauth.login(:login=>'foo@example.com', :password=>'invalid')
    end.must_raise Rodauth::InternalRequestError

    proc do
      app.rodauth.reset_password_request(:login=>'foo3@example.com')
    end.must_raise Rodauth::InternalRequestError

    proc do
      app.rodauth.reset_password_request(:account_login=>'foo3@example.com')
    end.must_raise Rodauth::InternalRequestError

    proc do
      app.rodauth.reset_password(:account_login=>'foo3@example.com')
    end.must_raise Rodauth::InternalRequestError

    proc do
      app.rodauth.reset_password(:account_login=>'foo@example.com')
    end.must_raise Rodauth::InternalRequestError

    app.rodauth.reset_password_request(:login=>'foo@example.com').must_be_nil
    link = email_link(/(\/reset-password\?key=.+)$/)

    app.rodauth.reset_password_request(:account_login=>'foo@example.com').must_be_nil
    link2 = email_link(/(\/reset-password\?key=.+)$/)
    link2.must_equal link

    visit link
    fill_in 'Password', :with=>'0123456'
    fill_in 'Confirm Password', :with=>'0123456'
    click_button 'Reset Password'
    page.find('#notice_flash').text.must_equal "Your password has been reset"

    login(:pass=>'0123456')
    page.body.must_include "Logged In"

    logout

    app.rodauth.reset_password_request(:account_login=>'foo@example.com').must_be_nil
    email_link(/(\/reset-password\?key=.+)$/)
    app.rodauth.reset_password(:account_login=>'foo@example.com', :password=>'01234567').must_be_nil

    login(:pass=>'01234567')
    page.body.must_include "Logged In"

    logout

    app.rodauth.reset_password_request(:login=>'foo@example.com').must_be_nil
    link = email_link(/(\/reset-password\?key=.+)$/)

    app.rodauth.reset_password(:account_login=>'foo@example.com', :password=>'012345678').must_be_nil

    visit link
    page.find('#error_flash').text.must_equal "There was an error resetting your password: invalid or expired password reset key"

    login(:pass=>'012345678')
    page.body.must_include "Logged In"

    app.rodauth.reset_password_request(:login=>'foo@example.com').must_be_nil
    link = email_link(/(\/reset-password\?key=.+)$/)
    key = link.split('=').last

    proc do
      app.rodauth.reset_password(:reset_password_key=>key[0...-1], :password=>'0123456789').must_be_nil
    end.must_raise Rodauth::InternalRequestError

    app.rodauth.reset_password(:reset_password_key=>key, :password=>'0123456789').must_be_nil

    login(:pass=>'0123456789')
    page.body.must_include "Logged In"
  end
end
