require_relative 'spec_helper'

describe 'Rodauth login feature' do
  it "should handle logins and logouts" do
    login_column = :f
    rodauth do
      enable :login, :logout
      login_column{login_column}
    end
    roda do |r|
      r.rodauth
      next unless rodauth.logged_in?
      r.root{view :content=>"Logged In"}
    end

    visit '/login'
    page.title.must_equal 'Login'
    page.all('[type=text]').first.value.must_equal ''
    page.find_by_id('password')[:autocomplete].must_equal 'current-password'

    login_column = :email
    login(:login=>'foo@example2.com', :visit=>false)
    page.find('#error_flash').text.must_equal 'There was an error logging in'
    page.html.must_include("no matching login")
    page.all('[type=email]').first.value.must_equal 'foo@example2.com'

    login(:pass=>'012345678', :visit=>false)
    page.find('#error_flash').text.must_equal 'There was an error logging in'
    page.html.must_include("invalid password")

    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.current_path.must_equal '/'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.html.must_include("Logged In")

    visit '/logout'
    page.title.must_equal 'Logout'

    click_button 'Logout'
    page.find('#notice_flash').text.must_equal 'You have been logged out'
    page.current_path.must_equal '/login'
  end

  it "should handle multi phase login (email first, then password)" do
    rodauth do
      enable :login, :logout
      use_multi_phase_login? true
      input_field_label_suffix ' (Required)'
      input_field_error_class ' bad-input'
      input_field_error_message_class 'err-msg'
      mark_input_fields_as_required? true
      field_attributes do |field|
        if field == 'login'
          'custom_field="custom_value"'
        else
          super(field)
        end
      end
      field_error_attributes do |field|
        if field == 'login'
          'custom_error_field="custom_error_value"'
        else
          super(field)
        end
      end
      formatted_field_error do |field, error|
        if field == 'login'
          super(field, error)
        else
          "<span class='err-msg2'>1#{error}2</span>"
        end
      end
    end
    roda do |r|
      r.rodauth
      next unless rodauth.logged_in?
      r.root{view :content=>"Logged In"}
    end

    visit '/login'
    page.title.must_equal 'Login'

    page.find('[custom_field=custom_value]').value.must_equal ''
    page.all('[custom_error_field=custom_error_value]').must_be_empty
    page.all('input[type=password]').must_be_empty
    fill_in 'Login (Required)', :with=>'foo2@example.com'
    click_button 'Login'
    page.find('#error_flash').text.must_equal 'There was an error logging in'
    page.find('[custom_field=custom_value]').value.must_equal 'foo2@example.com'
    page.find('[custom_error_field=custom_error_value]').value.must_equal 'foo2@example.com'
    page.find('[type=email]').value.must_equal 'foo2@example.com'
    page.find('.bad-input').value.must_equal 'foo2@example.com'
    page.find('.err-msg').text.must_equal 'no matching login'

    page.all('input[type=password]').must_be_empty
    fill_in 'Login (Required)', :with=>'foo@example.com'
    click_button 'Login'
    page.find('#notice_flash').text.must_equal 'Login recognized, please enter your password'

    page.all('[custom_field=custom_value]').must_be_empty
    page.all('[custom_error_field=custom_error_value]').must_be_empty
    page.all('[aria-invalid=true]').must_be_empty
    page.all('[aria-describedby]').must_be_empty
    page.find('[required=required]').value.to_s.must_equal ''
    page.all('input[type=text]').must_be_empty
    fill_in 'Password (Required)', :with=>'012345678'
    click_button 'Login'
    page.find('#error_flash').text.must_equal 'There was an error logging in'
    page.find('[aria-invalid=true]').value.to_s.must_equal ''
    page.find('[aria-describedby=password_error_message]').value.to_s.must_equal ''
    page.all('[custom_error_field=custom_error_value]').must_be_empty
    page.find('.err-msg2').text.must_equal '1invalid password2'

    page.all('input[type=text]').must_be_empty
    fill_in 'Password (Required)', :with=>'0123456789'
    click_button 'Login'
    page.current_path.must_equal '/'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.html.must_include("Logged In")

    visit '/logout'
    page.title.must_equal 'Logout'

    click_button 'Logout'
    page.find('#notice_flash').text.must_equal 'You have been logged out'
    page.current_path.must_equal '/login'
  end

  it "should allow returning to requested location when login was required" do
    rodauth do
      enable :login
      login_return_to_requested_location? true
      login_redirect '/'
    end
    roda do |r|
      r.rodauth
      r.get('page') do
        rodauth.require_login
        view :content=>"Passed Login Required: #{r.params['foo']}"
      end
    end

    visit '/page?foo=bar'
    login(:visit=>false)
    page.html.must_include 'Passed Login Required: bar'
  end

  it "should not return to requested location if a NON-GET request is used" do
    rodauth do
      enable :login
      login_return_to_requested_location? true
      login_redirect '/'
    end
    roda do |r|
      r.rodauth
      r.is('page') do
        rodauth.require_login if r.post?
        view :content=>"<form method='post'>#{rodauth.csrf_tag}<input type='submit' value ='Submit' /></form>"
      end
      r.root do
        "default"
      end
    end

    visit '/page?foo=bar'
    click_button 'Submit'
    login(:visit=>false)
    page.html.must_equal 'default'
  end

  it "should allow returning to custom location" do
    rodauth do
      enable :login
      login_return_to_requested_location? true
      login_return_to_requested_location_path do
        "#{request.path}?foo=bar"
      end
      login_redirect '/'
    end
    roda do |r|
      r.rodauth
      r.get('page') do
        rodauth.require_login
        view :content=>"Passed Login Required: #{r.params['foo']}"
      end
    end

    visit '/page'
    login(:visit=>false)
    page.html.must_include 'Passed Login Required: bar'
  end

  it "should not return to requested path size if it is too long" do
    path = "/a"*1024
    rodauth do
      enable :login, :logout
      login_return_to_requested_location? true
      login_return_to_requested_location_path do
        path
      end
      login_redirect '/'
    end
    roda do |r|
      r.rodauth
      rodauth.require_login
      ""
    end

    visit '/page'
    login(:visit=>false)
    page.current_path.must_equal path

    path = "/a"*4096
    logout
    visit '/page'
    login(:visit=>false)
    page.current_path.must_equal "/"
  end

  it "should not allow login to unverified account" do
    rodauth do
      enable :login
      skip_status_checks? false
    end
    roda do |r|
      r.rodauth
      next unless rodauth.logged_in?
      r.root{view :content=>"Logged In"}
    end

    DB[:accounts].update(:status_id=>1)
    login
    page.find('#error_flash').text.must_equal 'There was an error logging in'
    page.html.must_include("unverified account, please verify account before logging in")
  end

  it "should handle overriding login action" do
    rodauth do
      enable :login
    end
    roda do |r|
      r.post 'login' do
        if r.params['login'] == 'apple' && r.params['password'] == 'banana'
          session['user_id'] = 'pear'
          r.redirect '/'
        end
        r.redirect '/login'
      end
      r.rodauth
      next unless session['user_id'] == 'pear'
      r.root{"Logged In"}
    end

    login(:login=>'appl', :pass=>'banana')
    page.html.wont_match(/Logged In/)

    login(:login=>'apple', :pass=>'banan', :visit=>false)
    page.html.wont_match(/Logged In/)

    login(:login=>'apple', :pass=>'banana', :visit=>false)
    page.current_path.must_equal '/'
    page.html.must_include("Logged In")
  end

  it "should handle overriding some login attributes" do
    rodauth do
      enable :login
      account_from_login do |login|
        DB[:accounts].first if login == 'apple'
      end
      password_match? do |password|
        password == 'banana'
      end
      update_session do
        session['user_id'] = 'pear'
      end
      no_matching_login_message "no user"
      invalid_password_message "bad password"
    end
    roda do |r|
      r.rodauth
      next unless session['user_id'] == 'pear'
      r.root{"Logged In"}
    end

    login(:login=>'appl', :pass=>'banana')
    page.html.must_include("no user")

    login(:login=>'apple', :pass=>'banan', :visit=>false)
    page.html.must_include("bad password")

    fill_in 'Password', :with=>'banana'
    click_button 'Login'
    page.current_path.must_equal '/'
    page.html.must_include("Logged In")
  end

  it "should handle a prefix and some other login options" do
    rodauth do
      enable :login, :logout
      prefix '/auth'
      session_key 'login_email'
      account_from_session{DB[:accounts].first(:email=>session_value)}
      account_session_value{account[:email]}
      login_param{param('lp')}
      login_additional_form_tags "<input type='hidden' name='lp' value='l' />"
      password_param 'p'
      login_redirect{"/foo/#{account[:email]}"}
      logout_redirect '/auth/lin'
      login_route 'lin'
      logout_route 'lout'
    end
    no_freeze!
    roda do |r|
      r.on 'auth' do
        r.rodauth
      end
      r.get('restricted'){rodauth.require_login}
      next unless session['login_email'] =~ /example/
      r.get('foo', :email){|e| "Logged In: #{e}"}
    end
    app.plugin :render, :views=>'spec/views', :engine=>'str'

    visit '/auth/lin?lp=l'

    login(:login=>'foo@example2.com', :visit=>false)
    page.html.must_include("no matching login")

    login(:pass=>'012345678', :visit=>false)
    page.html.must_include("invalid password")

    login(:visit=>false)
    page.current_path.must_equal '/foo/foo@example.com'
    page.html.must_include("Logged In: foo@example.com")

    visit '/auth/lout'
    click_button 'Logout'
    page.current_path.must_equal '/auth/lin'

    visit '/restricted'
    page.current_path.must_equal '/auth/lin'
  end

  it "should use correct redirect paths when using prefix" do
    rodauth do
      enable :login, :logout
      prefix '/auth'
    end
    roda do |r|
      r.on 'auth' do
        r.rodauth
        rodauth.require_login
      end
      rodauth.send("#{r.remaining_path[1..-1]}_redirect")
    end

    visit '/login'
    page.html.must_equal '/'
    visit '/logout'
    page.html.must_equal '/auth/login'
    visit '/require_login'
    page.html.must_equal '/auth/login'

    visit '/auth'
    page.current_path.must_equal '/auth/login'
  end

  it "should allow manually logging in retrieved account" do
    rodauth do
      enable :login
    end
    roda do |r|
      r.get 'login' do
        rodauth.account_from_login("foo@example.com")
        rodauth.login('foo')
      end
      next unless rodauth.logged_in?
      r.root{view :content=>"Logged in via #{rodauth.authenticated_by.join(" ")}"}
    end

    visit '/login'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged in via foo'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
  end

  it "should support #_login for backwards compatibility" do
    warning = nil
    rodauth do
      enable :login
      auth_class_eval { define_method(:warn) { |msg| warning = msg } }
    end
    roda do |r|
      r.get 'login' do
        rodauth.account_from_login("foo@example.com")
        rodauth.send(:_login, 'foo')
      end
      next unless rodauth.logged_in?
      r.root{view :content=>"Logged in via #{rodauth.authenticated_by.join(" ")}"}
    end

    visit '/login'
    page.current_path.must_equal '/'
    page.html.must_include 'Logged in via foo'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    warning.must_equal "Deprecated #_login method called, use #login instead."
  end

  unless ENV['RODAUTH_NO_ARGON2'] == '1'
    begin
      require 'argon2'
    rescue LoadError
    else
      [false, true].each do |ph|
        it "should support argon2 secret #{'with account_password_hash_column' if ph}" do
          secret = "secret"
          rodauth do
            enable :argon2, :login, :create_account, :logout
            argon2_secret { secret }
            account_password_hash_column :ph if ph
          end
          roda do |r|
            r.rodauth
            r.root { view :content=>"Logged in" }
          end

          visit '/create-account'
          fill_in 'Login', :with=>'bar@example.com'
          fill_in 'Confirm Login', :with=>'bar@example.com'
          fill_in 'Password', :with=>'0123456789'
          fill_in 'Confirm Password', :with=>'0123456789'
          click_on 'Create Account'
          page.find('#notice_flash').text.must_equal "Your account has been created"

          logout
          login(:login=>'bar@example.com')
          page.find('#notice_flash').text.must_equal 'You have been logged in'

          logout
          secret = "secret2"
          login(:login=>'bar@example.com')
          page.find('#error_flash').text.must_equal 'There was an error logging in'
        end
      end

      describe "when a custom parallelism cost is specified for the argon2 password hash cost" do
        [true, false].each do |use_secret|
          it "should be able to login #{use_secret ? 'with' : 'without'} argon2 secret" do
            rodauth do
              enable :argon2, :login, :create_account, :logout

              # Custom p_cost of 8
              argon2_secret 'secret' if use_secret
              password_hash_cost({ t_cost: 2, m_cost: 16, p_cost: 8 })
            end

            roda do |r|
              r.rodauth
              r.root { view :content=>"Logged in" }
            end

            # We verify that we can create an account with custom cost configuration
            login = 'baz@example.com'
            pass = 'Abc123*'

            visit '/create-account'
            fill_in 'Login', with: login
            fill_in 'Confirm Login', with: login
            fill_in 'Password', with: pass
            fill_in 'Confirm Password', with: pass
            click_on 'Create Account'
            page.find('#notice_flash').text.must_equal "Your account has been created"

            logout

            # We verify that we can login with the custom config
            login(login: login, pass: pass)

            page.find('#notice_flash').text.must_equal 'You have been logged in'

            logout

            # We verify that subsequent logins keep working as well
            login(login: login, pass: pass)
            page.find('#notice_flash').text.must_equal 'You have been logged in'
          end

          describe 'and existing argon2 passwords exists with custom hash costs' do
            it 'should be able to login even if the hash cost changes' do
              custom_cost = { t_cost: 2, m_cost: 16, p_cost: 8 }

              rodauth do
                enable :argon2, :login, :create_account, :logout

                # Custom p_cost of 8
                argon2_secret 'secret'
                password_hash_cost { custom_cost }
              end

              roda do |r|
                r.rodauth
                r.root { view :content=>"Logged in" }
              end

              # We verify that we can create an account with custom cost configuration
              login = 'baz@example.com'
              pass = 'Abc123*'

              visit '/create-account'
              fill_in 'Login', with: login
              fill_in 'Confirm Login', with: login
              fill_in 'Password', with: pass
              fill_in 'Confirm Password', with: pass
              click_on 'Create Account'
              page.find('#notice_flash').text.must_equal "Your account has been created"

              logout

              # We verify that we can login with the custom config
              login(login: login, pass: pass)

              page.find('#notice_flash').text.must_equal 'You have been logged in'

              logout

              # change hash cost and try to login again
              custom_cost = { t_cost: 1, m_cost: 5, p_cost: 1 }

              login(login: login, pass: pass)

              page.find('#notice_flash').text.must_equal 'You have been logged in'

              logout

              # create new user with new hash cost and test login with both users
              login_2 = 'dogs@example.com'
              pass_2 = 'woofWoof123*'
              visit '/create-account'
              fill_in 'Login', with: login_2
              fill_in 'Confirm Login', with: login_2
              fill_in 'Password', with: pass_2
              fill_in 'Confirm Password', with: pass_2
              click_on 'Create Account'
              page.find('#notice_flash').text.must_equal "Your account has been created"

              # First user
              login(login: login, pass: pass)

              page.find('#notice_flash').text.must_equal 'You have been logged in'

              logout

              # Second user
              login(login: login_2, pass: pass_2)

              page.find('#notice_flash').text.must_equal 'You have been logged in'

              logout

              # bring custom cost to previous values and test both users
              custom_cost = { t_cost: 2, m_cost: 16, p_cost: 8 }

              # First user
              login(login: login, pass: pass)

              page.find('#notice_flash').text.must_equal 'You have been logged in'

              logout

              # Second user
              login(login: login_2, pass: pass_2)

              page.find('#notice_flash').text.must_equal 'You have been logged in'

              logout
            end
          end
        end
      end
    end
  end

  it "should login and logout via jwt" do
    rodauth do
      enable :login, :logout
      json_response_custom_error_status? false
      jwt_secret{proc{super()}.must_raise Rodauth::ConfigurationError; "1"}
    end
    roda(:jwt) do |r|
      r.rodauth
      response[CONTENT_TYPE_KEY] = 'application/json'
      rodauth.logged_in? ? '1' : '2'
    end

    json_request.must_equal [200, 2]

    res = json_request("/login", :login=>'foo@example2.com', :password=>'0123456789')
    res.must_equal [400, {'reason'=>"no_matching_login",'error'=>"There was an error logging in", "field-error"=>["login", "no matching login"]}]

    res = json_request("/login", :login=>'foo@example.com', :password=>'012345678')
    res.must_equal [400, {'reason'=>"invalid_password",'error'=>"There was an error logging in", "field-error"=>["password", "invalid password"]}]

    json_request("/login", :login=>'foo@example.com', :password=>'0123456789').must_equal [200, {"success"=>'You have been logged in'}]
    json_request.must_equal [200, 1]

    json_request("/logout").must_equal [200, {"success"=>'You have been logged out'}]
    json_request.must_equal [200, 2]
  end

  [:jwt, :json].each do |json|
    it "should login and logout via #{json} with custom error statuses" do
      rodauth do
        enable :login, :logout
      end
      roda(json) do |r|
        r.rodauth
        response[CONTENT_TYPE_KEY] = 'application/json'
        r.post('foo') do
          rodauth.require_login
          '3'
        end
        rodauth.logged_in? ? '1' : '2'
      end

      json_request.must_equal [200, 2]

      res = json_request("/foo")
      res.must_equal [401, {"reason"=>"login_required", "error"=>"Please login to continue"}]

      res = json_request("/login", :login=>'foo@example2.com', :password=>'0123456789')
      res.must_equal [401, {'reason'=>"no_matching_login",'error'=>"There was an error logging in", "field-error"=>["login", "no matching login"]}]

      res = json_request("/login", :login=>'foo@example.com', :password=>'012345678')
      res.must_equal [401, {'reason'=>"invalid_password",'error'=>"There was an error logging in", "field-error"=>["password", "invalid password"]}]

      json_request("/login", :login=>'foo@example.com', :password=>'0123456789').must_equal [200, {"success"=>'You have been logged in'}]
      json_request.must_equal [200, 1]

      res = json_request("/foo").must_equal [200, 3]

      json_request("/logout").must_equal [200, {"success"=>'You have been logged out'}]
      json_request.must_equal [200, 2]
    end
  end

  it "should allow checking login and password using internal requests" do
    rodauth do
      enable :login, :internal_request
    end
    roda do |r|
    end

    app.rodauth.valid_login_and_password?(:login=>'foo@example.com', :password=>'0123456789').must_equal true
    app.rodauth.valid_login_and_password?(:login=>'foo@example.com', :password=>'012345678').must_equal false
    app.rodauth.valid_login_and_password?(:login=>'foo@example2.com', :password=>'0123456789').must_equal false

    app.rodauth.valid_login_and_password?(:account_login=>'foo@example.com', :password=>'0123456789').must_equal true
    app.rodauth.valid_login_and_password?(:account_login=>'foo@example.com', :password=>'012345678').must_equal false

    proc do
      app.rodauth.valid_login_and_password?(:account_login=>'foo@example2.com', :password=>'0123456789')
    end.must_raise Rodauth::InternalRequestError

    app.rodauth.login(:account_login=>'foo@example.com', :password=>'0123456789').must_equal DB[:accounts].get(:id)

    proc do
      app.rodauth.login(:login=>'foo@example.com', :password=>'012345678')
    end.must_raise Rodauth::InternalRequestError

    proc do
      app.rodauth.login(:login=>'foo@example2.com', :password=>'0123456789')
    end.must_raise Rodauth::InternalRequestError

    app.rodauth.login(:account_login=>'foo@example.com', :password=>'0123456789').must_equal DB[:accounts].get(:id)

    proc do
      app.rodauth.login(:account_login=>'foo@example.com', :password=>'012345678')
    end.must_raise Rodauth::InternalRequestError
  end
end
