require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth disallow_password_reuse feature' do
  it "should disallow reuse of passwords" do
    rodauth do
      enable :login, :change_password, :disallow_password_reuse, :close_account
      change_password_requires_password? false
      close_account_requires_password? false
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

    8.times do |i|
      visit '/change-password'
      fill_in 'New Password', :with=>"password#{i}"
      fill_in 'Confirm Password', :with=>"password#{i}"
      click_button 'Change Password'
      page.find('#notice_flash').text.must_equal "Your password has been changed"
    end

    visit '/change-password'

    (1..6).each do |i|
      fill_in 'New Password', :with=>"password#{i}"
      fill_in 'Confirm Password', :with=>"password#{i}"
      click_button 'Change Password'
      page.html.must_include("invalid password, does not meet requirements (same as previous password)")
      page.find('#error_flash').text.must_equal "There was an error changing your password"
    end

    fill_in 'New Password', :with=>"password7"
    fill_in 'Confirm Password', :with=>"password7"
    click_button 'Change Password'
    page.html.must_include("invalid password, same as current password")

    fill_in 'New Password', :with=>'password0'
    fill_in 'Confirm Password', :with=>'password0'
    click_button 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"

    DB[:account_previous_password_hashes].count.must_equal 7
    visit '/close-account'
    click_button 'Close Account'
    DB[:account_previous_password_hashes].count.must_equal 0
  end

  it "should handle create account when account_password_hash_column is true" do
    rodauth do
      enable :login, :create_account, :change_password, :disallow_password_reuse
      account_password_hash_column :ph
      create_account_autologin? true
      change_password_requires_password? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'bar@example.com'
    fill_in 'Confirm Login', :with=>'bar@example.com'
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Create Account'
    page.current_path.must_equal '/'
    page.find('#notice_flash').text.must_equal "Your account has been created"

    visit '/change-password'
    fill_in 'New Password', :with=>"012345678"
    fill_in 'Confirm Password', :with=>"012345678"
    click_button 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"

    visit '/change-password'
    fill_in 'New Password', :with=>"0123456789"
    fill_in 'Confirm Password', :with=>"0123456789"
    click_button 'Change Password'
    page.html.must_include("invalid password, does not meet requirements (same as previous password)")
  end
end
