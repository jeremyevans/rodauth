require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth login feature' do
  it "should handle logins and logouts" do
    rodauth{enable :login, :logout}
    roda do |r|
      r.rodauth
      next unless session[:account_id]
      r.root{view :content=>"Logged In"}
    end

    visit '/login'
    page.title.must_equal 'Login'

    login(:login=>'foo@example2.com', :visit=>false)
    page.find('#error_flash').text.must_equal 'There was an error logging in'
    page.html.must_include("no matching login")

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

  it "should not allow login to unverified account" do
    rodauth do
      enable :login
      skip_status_checks? false
    end
    roda do |r|
      r.rodauth
      next unless session[:account_id]
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
        if r['login'] == 'apple' && r['password'] == 'banana'
          session[:user_id] = 'pear'
          r.redirect '/'
        end
        r.redirect '/login'
      end
      r.rodauth
      next unless session[:user_id] == 'pear'
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
        session[:user_id] = 'pear'
      end
      no_matching_login_message "no user"
      invalid_password_message "bad password"
    end
    roda do |r|
      r.rodauth
      next unless session[:user_id] == 'pear'
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
      prefix 'auth'
      session_key :login_email
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
      next unless session[:login_email] =~ /example/
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

  it "should login and logout via jwt" do
    rodauth do
      enable :login, :logout
      json_response_custom_error_status? false
      jwt_secret{proc{super()}.must_raise ArgumentError; "1"}
    end
    roda(:jwt) do |r|
      r.rodauth
      response['Content-Type'] = 'application/json'
      rodauth.logged_in? ? '1' : '2'
    end

    json_request.must_equal [200, 2]

    res = json_request("/login", :login=>'foo@example2.com', :password=>'0123456789')
    res.must_equal [400, {'error'=>"There was an error logging in", "field-error"=>["login", "no matching login"]}]

    res = json_request("/login", :login=>'foo@example.com', :password=>'012345678')
    res.must_equal [400, {'error'=>"There was an error logging in", "field-error"=>["password", "invalid password"]}]

    json_request("/login", :login=>'foo@example.com', :password=>'0123456789').must_equal [200, {"success"=>'You have been logged in'}]
    json_request.must_equal [200, 1]

    json_request("/logout").must_equal [200, {"success"=>'You have been logged out'}]
    json_request.must_equal [200, 2]
  end

  it "should login and logout via jwt with custom error statuses" do
    rodauth do
      enable :login, :logout
    end
    roda(:jwt) do |r|
      r.rodauth
      response['Content-Type'] = 'application/json'
      r.post('foo') do
        rodauth.require_login
        '3'
      end
      rodauth.logged_in? ? '1' : '2'
    end

    json_request.must_equal [200, 2]

    res = json_request("/foo")
    res.must_equal [401, {"error"=>"Please login to continue"}]

    res = json_request("/login", :login=>'foo@example2.com', :password=>'0123456789')
    res.must_equal [401, {'error'=>"There was an error logging in", "field-error"=>["login", "no matching login"]}]

    res = json_request("/login", :login=>'foo@example.com', :password=>'012345678')
    res.must_equal [401, {'error'=>"There was an error logging in", "field-error"=>["password", "invalid password"]}]

    json_request("/login", :login=>'foo@example.com', :password=>'0123456789').must_equal [200, {"success"=>'You have been logged in'}]
    json_request.must_equal [200, 1]

    res = json_request("/foo").must_equal [200, 3]

    json_request("/logout").must_equal [200, {"success"=>'You have been logged out'}]
    json_request.must_equal [200, 2]
  end
end
