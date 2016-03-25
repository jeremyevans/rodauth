require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth change_login feature' do
  it "should support changing logins for accounts" do
    Account.create(:email=>'foo2@example.com')
    require_password = false

    rodauth do
      enable :login, :logout, :change_login
      change_login_requires_password?{require_password}
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.current_path.must_equal '/'

    visit '/change-login'
    page.title.must_equal 'Change Login'

    fill_in 'Login', :with=>'foobar'
    fill_in 'Confirm Login', :with=>'foobar'
    click_button 'Change Login'
    page.find('#error_flash').text.must_equal "There was an error changing your login"
    page.html.must_include("invalid login, not a valid email address")
    page.current_path.must_equal '/change-login'

    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Confirm Login', :with=>'foo2@example.com'
    click_button 'Change Login'
    page.find('#error_flash').text.must_equal "There was an error changing your login"
    page.html.must_include("logins do not match")
    page.current_path.must_equal '/change-login'

    fill_in 'Login', :with=>'foo2@example.com'
    click_button 'Change Login'
    page.find('#error_flash').text.must_equal "There was an error changing your login"
    page.html.must_include("is already taken")
    page.current_path.must_equal '/change-login'

    fill_in 'Login', :with=>'foo3@example.com'
    fill_in 'Confirm Login', :with=>'foo3@example.com'
    click_button 'Change Login'
    page.find('#notice_flash').text.must_equal "Your login has been changed"
    page.current_path.must_equal '/'

    visit '/logout'
    click_button 'Logout'

    visit '/login'
    fill_in 'Login', :with=>'foo3@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.current_path.must_equal '/'

    require_password = true
    visit '/change-login'
    fill_in 'Password', :with=>'012345678'
    fill_in 'Login', :with=>'foo4@example.com'
    fill_in 'Confirm Login', :with=>'foo4@example.com'
    click_button 'Change Login'
    page.find('#error_flash').text.must_equal "There was an error changing your login"
    page.html.must_include("invalid password")
    page.current_path.must_equal '/change-login'

    fill_in 'Password', :with=>'0123456789'
    click_button 'Change Login'
    page.find('#notice_flash').text.must_equal "Your login has been changed"
    page.current_path.must_equal '/'

    visit '/logout'
    click_button 'Logout'

    visit '/login'
    fill_in 'Login', :with=>'foo4@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.current_path.must_equal '/'
  end
end
