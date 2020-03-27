require_relative 'spec_helper'

describe 'Rodauth disallow_password_reuse feature' do
  it "should disallow reuse of passwords" do
    table = :account_previous_password_hashes
    rodauth do
      enable :login, :change_password, :disallow_password_reuse, :close_account
      if ENV['RODAUTH_SEPARATE_SCHEMA']
        table = Sequel[:rodauth_test_password][:account_previous_password_hashes]
        previous_password_hash_table table
      end
      change_password_requires_password? false
      close_account_requires_password? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    login
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

    DB[table].get{count(:id)}.must_equal 7
    visit '/close-account'
    click_button 'Close Account'
    DB[table].get{count(:id)}.must_equal 0
  end

  [true, false].each do |ph|
    it "should handle create account when account_password_hash_column is #{ph}" do
      rodauth do
        enable :login, :create_account, :change_password, :disallow_password_reuse
        if ENV['RODAUTH_SEPARATE_SCHEMA']
          previous_password_hash_table Sequel[:rodauth_test_password][:account_previous_password_hashes]
        end
        account_password_hash_column :ph if ph
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

    it "should handle verify account when account_password_hash_column is #{ph}" do
      rodauth do
        enable :login, :verify_account, :change_password, :disallow_password_reuse
        if ENV['RODAUTH_SEPARATE_SCHEMA']
          previous_password_hash_table Sequel[:rodauth_test_password][:account_previous_password_hashes]
        end
        account_password_hash_column :ph if ph
        change_password_requires_password? false
      end
      roda do |r|
        r.rodauth
        r.root{view :content=>""}
      end

      visit '/create-account'
      fill_in 'Login', :with=>'bar@example.com'
      click_button 'Create Account'
      page.current_path.must_equal '/'
      page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
      link = email_link(/(\/verify-account\?key=.+)$/, 'bar@example.com')

      visit link
      fill_in 'Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'0123456789'
      click_button 'Verify Account'
      page.find('#notice_flash').text.must_equal "Your account has been verified"
      page.current_path.must_equal '/'

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

    it "should handle verify account when account_password_hash_column is #{ph} and verify_account_set_password? is true" do
      rodauth do
        enable :login, :verify_account, :change_password, :disallow_password_reuse
        if ENV['RODAUTH_SEPARATE_SCHEMA']
          previous_password_hash_table Sequel[:rodauth_test_password][:account_previous_password_hashes]
        end
        account_password_hash_column :ph if ph
        change_password_requires_password? false
        verify_account_set_password? true
      end
      roda do |r|
        r.rodauth
        r.root{view :content=>""}
      end

      visit '/create-account'
      fill_in 'Login', :with=>'bar@example.com'
      click_button 'Create Account'
      page.current_path.must_equal '/'
      page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
      link = email_link(/(\/verify-account\?key=.+)$/, 'bar@example.com')

      visit link
      fill_in 'Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'0123456789'
      click_button 'Verify Account'
      page.find('#notice_flash').text.must_equal "Your account has been verified"
      page.current_path.must_equal '/'

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
end
