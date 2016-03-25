require File.expand_path("spec_helper", File.dirname(__FILE__))

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

      visit '/login'
      fill_in 'Login', :with=>'foo@example.com'
      fill_in 'Password', :with=>'0123456789'
      click_button 'Login'
      page.current_path.must_equal '/'

      visit '/change-password'
      page.title.must_equal 'Change Password'

      fill_in 'Password', :with=>'0123456789'
      fill_in 'New Password', :with=>'0123456'
      fill_in 'Confirm Password', :with=>'0123456789'
      click_button 'Change Password'
      page.html.must_match(/passwords do not match/)
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

      visit '/logout'
      click_button 'Logout'

      visit '/login'
      fill_in 'Login', :with=>'foo@example.com'
      fill_in 'Password', :with=>'0123456789'
      click_button 'Login'
      page.html.must_match(/invalid password/)
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

      visit '/login'
      fill_in 'Login', :with=>'foo@example.com'
      fill_in 'Password', :with=>'012345678'
      click_button 'Login'
      page.current_path.must_equal '/'
    end
  end

  it "should support setting requirements for passwords" do
    rodauth do
      enable :login, :create_account, :change_password
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
    page.html.must_match(/invalid password, does not meet requirements/)
    page.find('#error_flash').text.must_equal "There was an error creating your account"
    page.current_path.must_equal '/create-account'

    fill_in 'Password', :with=>'banana'
    fill_in 'Confirm Password', :with=>'banana'
    click_button 'Create Account'

    visit '/login'
    fill_in 'Login', :with=>'foo2@example.com'
    fill_in 'Password', :with=>'banana'
    click_button 'Login'

    visit '/change-password'
    fill_in 'Password', :with=>'banana'
    fill_in 'New Password', :with=>'apple'
    fill_in 'Confirm Password', :with=>'apple'
    click_button 'Change Password'
    page.html.must_match(/invalid password, does not meet requirements/)
    page.find('#error_flash').text.must_equal "There was an error changing your password"
    page.current_path.must_equal '/change-password'

    fill_in 'Password', :with=>'banana'
    fill_in 'New Password', :with=>'my_banana_3'
    fill_in 'Confirm Password', :with=>'my_banana_3'
    click_button 'Change Password'
    page.current_path.must_equal '/'
  end
end
