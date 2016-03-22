require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth reset_password feature' do
  it "should support resetting passwords for accounts" do
    rodauth do
      enable :login, :reset_password
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'01234567'
    click_button 'Login'
    page.html.wont_match(/notice_flash/)

    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'01234567'
    click_button 'Login'

    click_button 'Request Password Reset'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to reset the password for your account"
    page.current_path.must_equal '/'

    link = email_link(/(\/reset-password\?key=.+)$/)
    visit link[0...-1]
    page.find('#error_flash').text.must_equal "invalid password reset key"

    visit link
    page.title.must_equal 'Reset Password'

    fill_in 'Password', :with=>'0123456'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Reset Password'
    page.html.must_match(/passwords do not match/)
    page.find('#error_flash').text.must_equal "There was an error resetting your password"
    page.current_path.must_equal '/reset-password'

    fill_in 'Password', :with=>'012'
    fill_in 'Confirm Password', :with=>'012'
    click_button 'Reset Password'
    page.html.must_match(/invalid password, does not meet requirements/)
    page.find('#error_flash').text.must_equal "There was an error resetting your password"
    page.current_path.must_equal '/reset-password'

    fill_in 'Password', :with=>'0123456'
    fill_in 'Confirm Password', :with=>'0123456'
    click_button 'Reset Password'
    page.find('#notice_flash').text.must_equal "Your password has been reset"
    page.current_path.must_equal '/'

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456'
    click_button 'Login'
    page.current_path.must_equal '/'
  end

  it "should support autologin when resetting passwords for accounts" do
    rodauth do
      enable :login, :reset_password
      reset_password_autologin? true
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'01234567'
    click_button 'Login'

    click_button 'Request Password Reset'
    link = email_link(/(\/reset-password\?key=.+)$/)
    visit link
    fill_in 'Password', :with=>'0123456'
    fill_in 'Confirm Password', :with=>'0123456'
    click_button 'Reset Password'
    page.find('#notice_flash').text.must_equal "Your password has been reset"
    page.body.must_match(/Logged In/)
  end
end
