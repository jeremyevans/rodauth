require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth remember feature' do
  it "should support login via remember token" do
    rodauth do
      enable :login, :remember
    end
    roda do |r|
      r.rodauth
      r.get 'load' do
        rodauth.load_memory
        r.redirect '/'
      end
      r.root do
        if rodauth.logged_in?
          if rodauth.logged_in_via_remember_key?
            "Logged In via Remember"
          else
            "Logged In Normally"
          end
        else
          "Not Logged In"
        end
      end
    end

    login
    page.body.must_equal 'Logged In Normally'

    visit '/load'
    page.body.must_equal 'Logged In Normally'

    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    page.body.must_equal 'Logged In Normally'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_equal 'Not Logged In'

    visit '/load'
    page.body.must_equal 'Logged In via Remember'

    key = get_cookie('_remember')
    visit '/remember'
    choose 'Forget Me'
    click_button 'Change Remember Setting'
    page.body.must_equal 'Logged In via Remember'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_equal 'Not Logged In'

    visit '/load'
    page.body.must_equal 'Not Logged In'

    set_cookie('_remember', key)
    visit '/load'
    page.body.must_equal 'Logged In via Remember'

    visit '/remember'
    choose 'Disable Remember Me'
    click_button 'Change Remember Setting'
    page.body.must_equal 'Logged In via Remember'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_equal 'Not Logged In'

    set_cookie('_remember', key)
    visit '/load'
    page.body.must_equal 'Not Logged In'
  end

  it "should forget remember token when explicitly logging out" do
    rodauth do
      enable :login, :logout, :remember
    end
    roda do |r|
      r.rodauth
      r.get 'load' do
        rodauth.load_memory
        r.redirect '/'
      end
      r.root{rodauth.logged_in? ? "Logged In#{session[:remembered]}" : "Not Logged In"}
    end

    login
    page.body.must_equal 'Logged In'

    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    page.body.must_equal 'Logged In'

    logout

    visit '/'
    page.body.must_equal 'Not Logged In'

    visit '/load'
    page.body.must_equal 'Not Logged In'
  end

  it "should support clearing remembered flag" do
    rodauth do
      enable :login, :remember
    end
    roda do |r|
      r.rodauth
      r.get 'load' do
        rodauth.load_memory
        r.redirect '/'
      end
      r.root do
        if rodauth.logged_in?
          if rodauth.logged_in_via_remember_key?
            "Logged In via Remember"
          else
            "Logged In Normally"
          end
        else
          "Not Logged In"
        end
      end
    end

    login
    page.body.must_equal 'Logged In Normally'

    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    page.body.must_equal 'Logged In Normally'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_equal 'Not Logged In'

    visit '/load'
    page.body.must_equal 'Logged In via Remember'

    visit '/remember?confirm=t'
    fill_in 'Password', :with=>'012345678'
    click_button 'Confirm Password'
    page.html.must_include("invalid password")

    fill_in 'Password', :with=>'0123456789'
    click_button 'Confirm Password'
    page.body.must_equal 'Logged In Normally'
  end

  it "should support extending remember token" do
    rodauth do
      enable :login, :remember
      extend_remember_deadline? true
    end
    roda do |r|
      r.rodauth
      r.get 'load' do
        rodauth.load_memory
        r.redirect '/'
      end
      r.root{rodauth.logged_in? ? "Logged In#{session[:remembered]}" : "Not Logged In"}
    end

    login

    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_equal 'Not Logged In'

    visit '/load'
    page.body.must_equal 'Logged Intrue'
  end

  it "should clear remember token when closing account" do
    rodauth do
      enable :login, :remember, :close_account
    end
    roda do |r|
      r.rodauth
      rodauth.load_memory
      r.root{rodauth.logged_in? ? "Logged In#{session[:remembered]}" : "Not Logged In"}
    end

    login

    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    DB[:account_remember_keys].count.must_equal 1

    visit '/close-account'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Close Account'
    DB[:account_remember_keys].count.must_equal 0
  end

  it "should not use remember token if the account is not open" do
    rodauth do
      enable :login, :remember
      skip_status_checks? false
    end
    roda do |r|
      r.rodauth
      r.get 'load' do
        rodauth.load_memory
        r.redirect '/'
      end
      r.root do
        if rodauth.logged_in?
          if rodauth.logged_in_via_remember_key?
            "Logged In via Remember"
          else
            "Logged In Normally"
          end
        else
          "Not Logged In"
        end
      end
    end

    login
    page.body.must_equal 'Logged In Normally'

    visit '/load'
    page.body.must_equal 'Logged In Normally'

    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    page.body.must_equal 'Logged In Normally'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_equal 'Not Logged In'

    DB[:accounts].update(:status_id=>3)

    visit '/load'
    page.body.must_equal 'Not Logged In'
  end

  it "should handle uniqueness errors raised when inserting remember token" do
    rodauth do
      enable :login, :remember
    end
    roda do |r|
      def rodauth.raised_uniqueness_violation(*) super; true; end
      r.rodauth
      r.get 'load' do
        rodauth.load_memory
        r.redirect '/'
      end
      r.root do
        if rodauth.logged_in?
          if rodauth.logged_in_via_remember_key?
            "Logged In via Remember"
          else
            "Logged In Normally"
          end
        else
          "Not Logged In"
        end
      end
    end

    login

    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    page.body.must_equal 'Logged In Normally'
  end

  it "should support login via remember token via jwt" do
    rodauth do
      enable :login, :remember
    end
    roda(:jwt) do |r|
      r.rodauth

      r.post 'load' do
        rodauth.load_memory
        [4]
      end

      if rodauth.logged_in?
        if rodauth.logged_in_via_remember_key?
          [1]
        else
          [2]
        end
      else
        [3]
      end
    end

    json_request.must_equal [200, [3]]
    json_login
    json_request.must_equal [200, [2]]

    json_request('/load').must_equal [200, [4]]
    json_request.must_equal [200, [2]]

    res = json_request('/remember', :remember=>'remember')
    res.must_equal [200, {'success'=>"Your remember setting has been updated"}]

    @authorization = nil
    json_request.must_equal [200, [3]]
    json_request('/load').must_equal [200, [4]]
    json_request.must_equal [200, [1]]

    cookie = @cookie
    res = json_request('/remember', :remember=>'forget')
    res.must_equal [200, {'success'=>"Your remember setting has been updated"}]
    json_request.must_equal [200, [1]]

    @cookie = nil
    @authorization = nil
    json_request.must_equal [200, [3]]

    json_request('/load').must_equal [200, [4]]
    json_request.must_equal [200, [3]]

    @cookie = cookie
    json_request('/load').must_equal [200, [4]]
    json_request.must_equal [200, [1]]

    res = json_request('/remember', :confirm=>'t', :password=>'123456')
    res.must_equal [400, {'error'=>"There was an error confirming your password", "field-error"=>["password", "invalid password"]}]

    res = json_request('/remember', :confirm=>'t', :password=>'0123456789')
    res.must_equal [200, {'success'=>"Your password has been confirmed"}]
    json_request.must_equal [200, [2]]

    res = json_request('/remember', :remember=>'disable')
    res.must_equal [200, {'success'=>"Your remember setting has been updated"}]

    @authorization = nil
    @cookie = nil
    json_request.must_equal [200, [3]]

    @cookie = cookie
    json_request('/load').must_equal [200, [4]]
    json_request.must_equal [200, [3]]
  end
end
