require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth create_account feature' do
  [false, true].each do |ph|
    it "should support creating accounts #{'with account_password_hash_column' if ph}" do
      rodauth do
        enable :login, :create_account
        account_password_hash_column :ph if ph
      end
      roda do |r|
        r.rodauth
        r.root{view :content=>""}
      end

      visit '/create-account'
      fill_in 'Login', :with=>'foo@example.com'
      fill_in 'Confirm Login', :with=>'foo@example.com'
      fill_in 'Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'0123456789'
      click_button 'Create Account'
      page.html.must_match(/is already taken/)
      page.find('#error_flash').text.must_equal "There was an error creating your account"
      page.current_path.must_equal '/create-account'

      fill_in 'Login', :with=>'foo@example2.com'
      fill_in 'Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'0123456789'
      click_button 'Create Account'
      page.html.must_match(/logins do not match/)
      page.find('#error_flash').text.must_equal "There was an error creating your account"
      page.current_path.must_equal '/create-account'

      fill_in 'Confirm Login', :with=>'foo@example2.com'
      fill_in 'Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'012345678'
      click_button 'Create Account'
      page.html.must_match(/passwords do not match/)
      page.find('#error_flash').text.must_equal "There was an error creating your account"
      page.current_path.must_equal '/create-account'

      fill_in 'Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'0123456789'
      click_button 'Create Account'
      page.find('#notice_flash').text.must_equal "Your account has been created"
      page.current_path.must_equal '/'

      visit '/login'
      fill_in 'Login', :with=>'foo@example2.com'
      fill_in 'Password', :with=>'0123456789'
      click_button 'Login'
      page.current_path.must_equal '/'
    end
  end

  it "should support autologin after account creation" do
    rodauth do
      enable :login, :create_account
      create_account_autologin? true
    end
    roda do |r|
      r.rodauth
      next unless session[:account_id]
      r.root{view :content=>"Logged In: #{Account[session[:account_id]].email}"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo2@example.com'
    fill_in 'Confirm Login', :with=>'foo2@example.com'
    fill_in 'Password', :with=>'apple2'
    fill_in 'Confirm Password', :with=>'apple2'
    click_button 'Create Account'
    page.html.must_match(/Logged In: foo2@example\.com/)
  end
end
