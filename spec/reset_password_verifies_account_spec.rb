require_relative 'spec_helper'

describe 'Rodauth reset_password_verifies_account feature' do
  it "should support implicit verification when resetting passwords for unverified accounts" do
    rodauth do
      enable :login, :logout, :reset_password_verifies_account
      reset_password_autologin? true
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In" : "Not Logged"}
    end

    DB[:accounts].update(:status_id=>1)
    DB[:account_verification_keys].insert(:id=>DB[:accounts].get(:id), :key=>'test')

    2.times do |i|
      visit '/reset-password-request'
      fill_in 'Login', :with=>'foo@example.com'
      click_button 'Request Password Reset'
      page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to reset the password for your account"

      link = email_link(/(\/reset-password\?key=.+)$/)
      visit link
      fill_in 'Password', :with=>"0123456#{i}"
      fill_in 'Confirm Password', :with=>"0123456#{i}"
      click_button 'Reset Password'
      page.find('#notice_flash').text.must_equal "Your password has been reset"
      page.body.must_include("Logged In")

      DB[:accounts].get(:status_id).must_equal 2
      DB[:account_verification_keys].count.must_equal 0
      logout
    end
  end
end
