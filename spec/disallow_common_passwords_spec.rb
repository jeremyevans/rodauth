require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth disallow common passwords feature' do
  it "should check that password used is not one of the most common" do
    rodauth do
      enable :login, :change_password, :disallow_common_passwords
      change_password_requires_password? false
      password_minimum_length 1
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    login
    page.current_path.must_equal '/'

    visit '/change-password'

    bad_password_file = File.join(File.dirname(File.dirname(File.expand_path(__FILE__))), 'dict', 'top-10_000-passwords.txt')
    File.read(bad_password_file).split.shuffle.take(5).each do |pass|
      fill_in 'New Password', :with=>pass
      fill_in 'Confirm Password', :with=>pass
      click_button 'Change Password'
      page.html.must_include("invalid password, does not meet requirements (is one of the most common passwords)")
      page.find('#error_flash').text.must_equal "There was an error changing your password"
    end

    fill_in 'New Password', :with=>'footpassword'
    fill_in 'Confirm Password', :with=>'footpassword'
    click_button 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"
  end

  it "should check that password used is not one of the most common with custom password set" do
    rodauth do
      enable :login, :change_password, :disallow_common_passwords
      change_password_requires_password? false
      most_common_passwords ['foobarbaz']
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    login
    page.current_path.must_equal '/'

    visit '/change-password'

    fill_in 'New Password', :with=>'foobarbaz'
    fill_in 'Confirm Password', :with=>'foobarbaz'
    click_button 'Change Password'
    page.html.must_include("invalid password, does not meet requirements (is one of the most common passwords)")
    page.find('#error_flash').text.must_equal "There was an error changing your password"

    fill_in 'New Password', :with=>'footpassword'
    fill_in 'Confirm Password', :with=>'footpassword'
    click_button 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"
  end

  it "should check that password used is not one of the most common with custom check" do
    rodauth do
      enable :login, :change_password, :disallow_common_passwords
      change_password_requires_password? false
      most_common_passwords_file nil
      password_one_of_most_common? do |password|
        password == 'foobarbaz'
      end
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    login
    page.current_path.must_equal '/'

    visit '/change-password'

    fill_in 'New Password', :with=>'foobarbaz'
    fill_in 'Confirm Password', :with=>'foobarbaz'
    click_button 'Change Password'
    page.html.must_include("invalid password, does not meet requirements (is one of the most common passwords)")
    page.find('#error_flash').text.must_equal "There was an error changing your password"

    fill_in 'New Password', :with=>'footpassword'
    fill_in 'Confirm Password', :with=>'footpassword'
    click_button 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"
  end
end
