require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth account expiration feature' do
  it "should force account expiration after x number of days" do
    rodauth do
      enable :login, :logout, :account_expiration
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In#{rodauth.last_account_login_at.strftime('%m%d%y')}" : "Not Logged"}
    end

    now = Time.now
    2.times do
      visit '/login'
      fill_in 'Login', :with=>'foo@example.com'
      fill_in 'Password', :with=>'0123456789'
      click_button 'Login'
      page.body.must_include "Logged In#{now.strftime('%m%d%y')}"

      visit '/logout'
      click_button 'Logout'
    end

    DB[:account_activity_times].update(:last_login_at => Time.now - 181*86400)

    2.times do
      visit '/login'
      fill_in 'Login', :with=>'foo@example.com'
      fill_in 'Password', :with=>'0123456789'
      click_button 'Login'
      page.body.must_include 'Not Logged'
      page.find('#notice_flash').text.must_equal "You cannot log into this account as it has expired"
    end
  end

  it "should use last activity time if configured" do
    rodauth do
      enable :login, :logout, :account_expiration
      expire_account_on_last_activity? true
      account_expiration_notice_flash{"Account expired on #{account_expired_at.strftime('%m%d%y')}"}
    end
    roda do |r|
      r.is("a"){view :content=>"Logged In#{rodauth.last_account_activity_at.strftime('%m%d%y')}"}
      rodauth.update_last_activity
      r.rodauth
      r.root{view :content=>rodauth.logged_in? ? "Logged In#{rodauth.last_account_activity_at.strftime('%m%d%y')}" : 'Not Logged'}
    end

    now = Time.now
    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.body.must_include "Logged In#{now.strftime('%m%d%y')}"

    DB[:account_activity_times].count.must_equal 1
    DB[:account_activity_times].delete

    visit '/'
    DB[:account_activity_times].count.must_equal 1

    t1 = now - 179*86400
    DB[:account_activity_times].update(:last_activity_at => t1)
    visit '/a'
    page.body.must_include "Logged In#{t1.strftime('%m%d%y')}"

    visit '/logout'
    click_button 'Logout'

    t2 = now - 181*86400
    DB[:account_activity_times].update(:last_activity_at => t2).must_equal 1

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.body.must_include 'Not Logged'
    page.find('#notice_flash').text.must_equal "Account expired on #{now.strftime('%m%d%y')}"

    DB[:account_activity_times].update(:expired_at=>t1).must_equal 1

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.body.must_include 'Not Logged'
    page.find('#notice_flash').text.must_equal "Account expired on #{t1.strftime('%m%d%y')}"
  end
end
