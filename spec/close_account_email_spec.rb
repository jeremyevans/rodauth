require_relative 'spec_helper'

describe 'Rodauth close_account_email feature' do
  it "should email when an account is closed" do
    rodauth do
      enable :login, :close_account_email
    end
    roda do |r|
      r.rodauth
      ""
    end

    login
    visit '/close-account'
    fill_in 'Password', :with=>'0123456789'
    click_button "Close Account"
    email = email_sent
    email.to.must_equal ["foo@example.com"]
    email.subject.must_equal "Account Closed"
    email.body.to_s.must_equal <<EMAIL
Someone (hopefully you) has closed the account associated to this
email address.
EMAIL
  end
end
