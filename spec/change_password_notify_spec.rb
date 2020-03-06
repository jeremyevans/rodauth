require_relative 'spec_helper'

describe 'Rodauth change_password_notify feature' do
  it "should email when using change password" do
    rodauth do
      enable :login, :logout, :change_password_notify
      change_password_requires_password? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    login
    page.current_path.must_equal '/'

    visit '/change-password'
    fill_in 'New Password', :with=>'0123456'
    fill_in 'Confirm Password', :with=>'0123456'
    click_button 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"

    page.current_path.must_equal '/'
    msgs = Mail::TestMailer.deliveries
    msgs.length.must_equal 1
    msgs.first.to.first.must_equal 'foo@example.com'
    msgs.first.body.to_s.must_equal <<EMAIL
Someone (hopefully you) has changed the password for the account
associated to this email address.
EMAIL
    msgs.clear
  end
end
