require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth password expiration feature' do
  it "should force password changes after x number of days" do
    rodauth do
      enable :login, :logout, :change_password, :reset_password, :password_expiration
      allow_password_change_after 1000
      change_password_requires_password? false
    end
    roda do |r|
      r.rodauth
      rodauth.require_current_password if rodauth.logged_in?
      r.root{view :content=>""}
    end

    login(:pass=>'01234567')
    click_button 'Request Password Reset'
    link = email_link(/(\/reset-password\?key=.+)$/)

    visit link
    page.current_path.must_equal '/reset-password'

    login
    page.current_path.must_equal '/'

    visit '/change-password'
    fill_in 'New Password', :with=>'banana'
    fill_in 'Confirm Password', :with=>'banana'
    click_button 'Change Password'
    page.current_path.must_equal '/'

    visit '/change-password'
    page.current_path.must_equal '/'
    page.find('#notice_flash').text.must_equal "Your password cannot be changed yet"

    logout

    visit link
    page.current_path.must_equal '/'
    page.find('#notice_flash').text.must_equal "Your password cannot be changed yet"

    DB[:account_password_change_times].update(:changed_at=>Time.now - 1100)

    visit link
    page.current_path.must_equal '/reset-password'

    login(:pass=>'banana')
    page.current_path.must_equal '/'

    visit '/change-password'
    page.current_path.must_equal '/change-password'

    logout

    DB[:account_password_change_times].update(:changed_at=>Time.now - 91*86400)

    login(:pass=>'banana')
    page.current_path.must_equal '/change-password'
    page.find('#notice_flash').text.must_equal "Your password has expired and needs to be changed"

    visit '/foo'
    page.current_path.must_equal '/change-password'
    page.find('#notice_flash').text.must_equal "Your password has expired and needs to be changed"

    fill_in 'New Password', :with=>'banana2'
    fill_in 'Confirm Password', :with=>'banana2'
    click_button 'Change Password'
    page.current_path.must_equal '/'

    visit '/change-password'
    page.current_path.must_equal '/'
    page.find('#notice_flash').text.must_equal "Your password cannot be changed yet"

    logout

    visit link
    page.current_path.must_equal '/'
    page.find('#notice_flash').text.must_equal "Your password cannot be changed yet"
  end

  it "should update password changed at when creating accounts" do
    rodauth do
      enable :login, :create_account, :password_expiration
      allow_password_change_after 1000
      account_password_hash_column :ph
      create_account_autologin? true
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo2@example.com'
    fill_in 'Confirm Login', :with=>'foo2@example.com'
    fill_in 'Password', :with=>'apple2'
    fill_in 'Confirm Password', :with=>'apple2'
    click_button 'Create Account'

    visit '/change-password'
    page.current_path.must_equal '/'
    page.find('#notice_flash').text.must_equal "Your password cannot be changed yet"
  end

  it "should remove password expiration data when closing accounts" do
    rodauth do
      enable :create_account, :close_account, :password_expiration
      close_account_requires_password? false
      create_account_autologin? true
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo2@example.com'
    fill_in 'Confirm Login', :with=>'foo2@example.com'
    fill_in 'Password', :with=>'apple2'
    fill_in 'Confirm Password', :with=>'apple2'
    click_button 'Create Account'

    DB[:account_password_change_times].count.must_equal 1
    visit '/close-account'
    click_button 'Close Account'
    DB[:account_password_change_times].count.must_equal 0
  end
end
