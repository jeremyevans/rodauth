require_relative 'spec_helper'

describe 'Rodauth reset_password_notify feature' do
  it "should send email when password is reset" do
    rodauth do
      enable :reset_password_notify
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/login'
    login(:pass=>'01234567', :visit=>false)
    click_button 'Request Password Reset'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to reset the password for your account"

    visit email_link(/(\/reset-password\?key=.+)$/)
    fill_in 'Password', :with=>'0123456'
    fill_in 'Confirm Password', :with=>'0123456'
    click_button 'Reset Password'
    page.find('#notice_flash').text.must_equal "Your password has been reset"

    email = email_sent
    email.subject.must_equal "Password Reset Completed"
    email.body.to_s.must_equal <<EMAIL
Someone (hopefully you) has reset the password for the account
associated to this email address.
EMAIL
  end
end
