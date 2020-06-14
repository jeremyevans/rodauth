require_relative 'spec_helper'

describe 'Rodauth disallow common disposable email providers' do
  it 'should fail when using a block provider' do
    rodauth do
      enable :login, :create_account, :disposable_email
    end

    roda do |r|
      r.rodauth
      r.root { view content: '' }
    end

    visit '/create-account'
    fill_in 'Login', with: 'foo@jetable.org'
    fill_in 'Confirm Login', with: 'foo@jetable.org'
    fill_in 'Password', with: '0123456789'
    fill_in 'Confirm Password', with: '0123456789'
    click_button 'Create Account'
    page.html.must_include("invalid login, is a disposable email")
    page.find('#error_flash').text.must_equal "There was an error creating your account"
    page.current_path.must_equal '/create-account'
  end

  it 'should this log in with a valid provider' do
    rodauth do
      enable :login, :create_account, :disposable_email
    end

    roda do |r|
      r.rodauth
      r.root { view content: '' }
    end

    visit '/create-account'
    fill_in 'Login', with: 'foo@gmail.com'
    fill_in 'Confirm Login', with: 'foo@gmail.com'
    fill_in 'Password', with: '0123456789'
    fill_in 'Confirm Password', with: '0123456789'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "Your account has been created"
    page.current_path.must_equal '/'
  end
end
