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
      r.root{rodauth.logged_in? ? "Logged In#{session[:remembered]}" : "Not Logged In"}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.body.must_equal 'Logged In'

    visit '/load'
    page.body.must_equal 'Logged In'

    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    page.body.must_equal 'Logged In'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_equal 'Not Logged In'

    visit '/load'
    page.body.must_equal 'Logged Intrue'

    key = get_cookie('_remember')
    visit '/remember'
    choose 'Forget Me'
    click_button 'Change Remember Setting'
    page.body.must_equal 'Logged Intrue'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_equal 'Not Logged In'

    visit '/load'
    page.body.must_equal 'Not Logged In'

    set_cookie('_remember', key)
    visit '/load'
    page.body.must_equal 'Logged Intrue'

    visit '/remember'
    choose 'Disable Remember Me'
    click_button 'Change Remember Setting'
    page.body.must_equal 'Logged Intrue'

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

    remove_cookie('rack.session')
    visit '/'
    page.body.must_equal 'Not Logged In'

    visit '/load'
    page.body.must_equal 'Logged Intrue'

    visit '/remember?confirm=t'
    fill_in 'Password', :with=>'012345678'
    click_button 'Confirm Password'
    page.html.must_match(/invalid password/)

    fill_in 'Password', :with=>'0123456789'
    click_button 'Confirm Password'
    page.body.must_equal 'Logged In'
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
end
