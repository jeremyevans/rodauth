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

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
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

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.body.must_equal 'Logged In'

    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    page.body.must_equal 'Logged In'

    visit '/logout'
    click_button 'Logout'

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

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
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

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'

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

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'

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

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
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
end
