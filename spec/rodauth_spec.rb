$: << 'lib'

if ENV['COVERAGE']
  require 'coverage'
  require 'simplecov'

  def SimpleCov.rodauth_coverage(opts = {})
    start do
      add_filter "/spec/"
      add_group('Missing'){|src| src.covered_percent < 100}
      add_group('Covered'){|src| src.covered_percent == 100}
      yield self if block_given?
    end
  end

  ENV.delete('COVERAGE')
  SimpleCov.rodauth_coverage
end

require 'rubygems'
require 'capybara'
require 'capybara/dsl'
require 'rack/test'
gem 'minitest'
require 'minitest/autorun'
require 'minitest/hooks/default'

require 'roda'
require 'sequel'
require 'bcrypt'
require 'mail'
require 'logger'
require 'tilt/string'

DB = Sequel.postgres(:user=>'rodauth_test', :password=>'rodauth_test')
#DB.loggers << Logger.new($stdout)

ENV['RACK_ENV'] = 'test'

::Mail.defaults do
  delivery_method :test
end

class Account < Sequel::Model
  plugin :validation_helpers

  def validate
    super
    validates_unique(:email){|ds| ds.where(:status_id=>[1,2])} unless status_id == 3
  end
end

Base = Class.new(Roda)
Base.plugin :render, :layout=>{:path=>'spec/views/layout.str'}
Base.plugin(:not_found){raise "path #{request.path_info} not found"}
Base.use Rack::Session::Cookie, :secret=>'0123456789'
class Base
  attr_writer :title
end

class Minitest::HooksSpec
  include Rack::Test::Methods
  include Capybara::DSL

  attr_reader :app

  def app=(app)
    @app = Capybara.app = app
  end

  def rodauth(&block)
    @rodauth_block = block
  end

  def roda(&block)
    app = Class.new(Base)
    rodauth_block = @rodauth_block
    app.plugin(:rodauth) do
      title_instance_variable :@title
      instance_exec(&rodauth_block)
    end
    app.route(&block)
    self.app = app
  end

  def remove_cookie(key)
    page.driver.browser.rack_mock_session.cookie_jar.delete(key)
  end

  def get_cookie(key)
    page.driver.browser.rack_mock_session.cookie_jar[key]
  end

  def set_cookie(key, value)
    page.driver.browser.rack_mock_session.cookie_jar[key] = value
  end

  around do |&block|
    DB.transaction(:rollback=>:always, :savepoint=>true, :auto_savepoint=>true){super(&block)}
  end
  
  around(:all) do |&block|
    DB.transaction(:rollback=>:always){super(&block)}
  end
  
  after do
    Capybara.reset_sessions!
    Capybara.use_default_driver
  end
end

describe 'Rodauth' do
  before(:all) do
    hash = BCrypt::Password.create('0123456789', :cost=>BCrypt::Engine::MIN_COST)
    DB[:account_password_hashes].insert(:id=>Account.create(:email=>'foo@example.com', :status_id=>2, :ph=>hash).id, :password_hash=>hash)
  end

  it "should handle logins and logouts" do
    rodauth{enable :login, :logout}
    roda do |r|
      r.rodauth
      next unless session[:account_id]
      r.root{view :content=>"Logged In"}
    end

    visit '/login'
    page.title.must_equal 'Login'

    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.find('#error_flash').text.must_equal 'There was an error logging in'
    page.html.must_match(/no matching login/)

    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'012345678'
    click_button 'Login'
    page.find('#error_flash').text.must_equal 'There was an error logging in'
    page.html.must_match(/invalid password/)

    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.current_path.must_equal '/'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.html.must_match(/Logged In/)

    visit '/logout'
    page.title.must_equal 'Logout'

    click_button 'Logout'
    page.find('#notice_flash').text.must_equal 'You have been logged out'
    page.current_path.must_equal '/login'
  end

  it "should not allow login to unverified account" do
    rodauth{enable :login}
    roda do |r|
      r.rodauth
      next unless session[:account_id]
      r.root{view :content=>"Logged In"}
    end

    visit '/login'
    page.title.must_equal 'Login'

    Account.first.update(:status_id=>1)
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.find('#error_flash').text.must_equal 'There was an error logging in'
    page.html.must_match(/unverified account, please verify account before logging in/)
  end

  it "should handle overriding login action" do
    rodauth do
      enable :login
      login_post_block do |r, _|
        if r['login'] == 'apple' && r['password'] == 'banana'
          session[:user_id] = 'pear'
          r.redirect '/'
        end
        r.redirect '/login'
      end
    end
    roda do |r|
      r.rodauth
      next unless session[:user_id] == 'pear'
      r.root{"Logged In"}
    end

    visit '/login'

    fill_in 'Login', :with=>'appl'
    fill_in 'Password', :with=>'banana'
    click_button 'Login'
    page.html.wont_match(/Logged In/)

    fill_in 'Login', :with=>'apple'
    fill_in 'Password', :with=>'banan'
    click_button 'Login'
    page.html.wont_match(/Logged In/)

    fill_in 'Login', :with=>'apple'
    fill_in 'Password', :with=>'banana'
    click_button 'Login'
    page.current_path.must_equal '/'
    page.html.must_match(/Logged In/)
  end

  it "should handle overriding some login attributes" do
    rodauth do
      enable :login
      account_from_login do |login|
        Account.first if login == 'apple'
      end
      password_match? do |password|
        password == 'banana'
      end
      update_session do
        session[:user_id] = 'pear'
      end
      no_matching_login_message "no user"
      invalid_password_message "bad password"
    end
    roda do |r|
      r.rodauth
      next unless session[:user_id] == 'pear'
      r.root{"Logged In"}
    end

    visit '/login'

    fill_in 'Login', :with=>'appl'
    fill_in 'Password', :with=>'banana'
    click_button 'Login'
    page.html.must_match(/no user/)

    fill_in 'Login', :with=>'apple'
    fill_in 'Password', :with=>'banan'
    click_button 'Login'
    page.html.must_match(/bad password/)

    fill_in 'Password', :with=>'banana'
    click_button 'Login'
    page.current_path.must_equal '/'
    page.html.must_match(/Logged In/)
  end

  it "should handle a prefix and some other login options" do
    rodauth do
      enable :login, :logout
      prefix 'auth'
      session_key :login_email
      account_from_session{Account.first(:email=>session_value)}
      account_session_value{account.email}
      login_param{request['lp']}
      password_param 'p'
      login_redirect{"/foo/#{account.email}"}
      logout_redirect '/auth/lin'
      login_route 'lin'
      logout_route 'lout'
    end
    roda do |r|
      r.on 'auth' do
        r.rodauth
      end
      next unless session[:login_email] =~ /example/
      r.get('foo/:email'){|e| "Logged In: #{e}"}
    end
    app.plugin :render, :views=>'spec/views', :engine=>'str'

    visit '/auth/lin?lp=l'

    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.html.must_match(/no matching login/)

    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'012345678'
    click_button 'Login'
    page.html.must_match(/invalid password/)

    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.current_path.must_equal '/foo/foo@example.com'
    page.html.must_match(/Logged In: foo@example\.com/)

    visit '/auth/lout'
    click_button 'Logout'
    page.current_path.must_equal '/auth/lin'
  end

  it "should support closing accounts" do
    rodauth do
      enable :login, :close_account
    end
    roda do |r|
      r.rodauth
      r.root{""}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.current_path.must_equal '/'

    visit '/close-account'
    click_button 'Close Account'
    page.current_path.must_equal '/'

    Account.select_map(:status_id).must_equal [3]
  end

  it "should support closing accounts with overrides" do
    rodauth do
      enable :login, :close_account
      close_account do
        account.email = 'foo@bar.com'
        super()
      end
      close_account_route 'close'
      close_account_redirect '/login'
    end
    roda do |r|
      r.rodauth
      r.root{""}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.current_path.must_equal '/'

    visit '/close'
    page.title.must_equal 'Close Account'
    click_button 'Close Account'
    page.find('#notice_flash').text.must_equal "Your account has been closed"
    page.current_path.must_equal '/login'

    Account.select_map(:status_id).must_equal [3]
    Account.select_map(:email).must_equal ['foo@bar.com']
  end

  [false, true].each do |ph|
    it "should support creating accounts #{'with account_password_hash_column' if ph}" do
      rodauth do
        enable :login, :create_account
        account_password_hash_column :ph if ph
      end
      roda do |r|
        r.rodauth
        r.root{view :content=>""}
      end

      visit '/create-account'
      fill_in 'Login', :with=>'foo@example.com'
      fill_in 'Confirm Login', :with=>'foo@example.com'
      fill_in 'Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'0123456789'
      click_button 'Create Account'
      page.html.must_match(/is already taken/)
      page.find('#error_flash').text.must_equal "There was an error creating your account"
      page.current_path.must_equal '/create-account'

      fill_in 'Login', :with=>'foo@example2.com'
      fill_in 'Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'0123456789'
      click_button 'Create Account'
      page.html.must_match(/logins do not match/)
      page.find('#error_flash').text.must_equal "There was an error creating your account"
      page.current_path.must_equal '/create-account'

      fill_in 'Confirm Login', :with=>'foo@example2.com'
      fill_in 'Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'012345678'
      click_button 'Create Account'
      page.html.must_match(/passwords do not match/)
      page.find('#error_flash').text.must_equal "There was an error creating your account"
      page.current_path.must_equal '/create-account'

      fill_in 'Password', :with=>'0123456789'
      fill_in 'Confirm Password', :with=>'0123456789'
      click_button 'Create Account'
      page.find('#notice_flash').text.must_equal "Your account has been created"
      page.current_path.must_equal '/'

      visit '/login'
      fill_in 'Login', :with=>'foo@example2.com'
      fill_in 'Password', :with=>'0123456789'
      click_button 'Login'
      page.current_path.must_equal '/'
    end

    it "should support changing passwords for accounts #{'with account_password_hash_column' if ph}" do
      rodauth do
        enable :login, :logout, :change_password
        account_password_hash_column :ph if ph
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

      visit '/change-password'
      page.title.must_equal 'Change Password'

      fill_in 'Password', :with=>'0123456'
      fill_in 'Confirm Password', :with=>'0123456789'
      click_button 'Change Password'
      page.html.must_match(/passwords do not match/)
      page.find('#error_flash').text.must_equal "There was an error changing your password"
      page.current_path.must_equal '/change-password'

      fill_in 'Password', :with=>'0123456'
      fill_in 'Confirm Password', :with=>'0123456'
      click_button 'Change Password'
      page.find('#notice_flash').text.must_equal "Your password has been changed"
      page.current_path.must_equal '/'

      visit '/logout'
      click_button 'Logout'

      visit '/login'
      fill_in 'Login', :with=>'foo@example.com'
      fill_in 'Password', :with=>'0123456789'
      click_button 'Login'
      page.html.must_match(/invalid password/)
      page.current_path.must_equal '/login'

      fill_in 'Password', :with=>'0123456'
      click_button 'Login'
      page.current_path.must_equal '/'
    end
  end

  it "should support changing logins for accounts" do
    Account.create(:email=>'foo2@example.com')

    rodauth do
      enable :login, :logout, :change_login
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

    visit '/change-login'
    page.title.must_equal 'Change Login'

    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Confirm Login', :with=>'foo2@example.com'
    click_button 'Change Login'
    page.find('#error_flash').text.must_equal "There was an error changing your login"
    page.html.must_match(/logins do not match/)
    page.current_path.must_equal '/change-login'

    fill_in 'Login', :with=>'foo2@example.com'
    click_button 'Change Login'
    page.find('#error_flash').text.must_equal "There was an error changing your login"
    page.html.must_match(/is already taken/)
    page.current_path.must_equal '/change-login'

    fill_in 'Login', :with=>'foo3@example.com'
    fill_in 'Confirm Login', :with=>'foo3@example.com'
    click_button 'Change Login'
    page.find('#notice_flash').text.must_equal "Your login has been changed"
    page.current_path.must_equal '/'

    visit '/logout'
    click_button 'Logout'

    visit '/login'
    fill_in 'Login', :with=>'foo3@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.current_path.must_equal '/'
  end

  it "should support setting requirements for passwords" do
    rodauth do
      enable :login, :create_account, :change_password
      password_meets_requirements? do |password|
        password =~ /banana/
      end
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo2@example.com'
    fill_in 'Confirm Login', :with=>'foo2@example.com'
    fill_in 'Password', :with=>'apple'
    fill_in 'Confirm Password', :with=>'apple'
    click_button 'Create Account'
    page.html.must_match(/invalid password, does not meet requirements/)
    page.find('#error_flash').text.must_equal "There was an error creating your account"
    page.current_path.must_equal '/create-account'

    fill_in 'Password', :with=>'banana'
    fill_in 'Confirm Password', :with=>'banana'
    click_button 'Create Account'

    visit '/login'
    fill_in 'Login', :with=>'foo2@example.com'
    fill_in 'Password', :with=>'banana'
    click_button 'Login'

    visit '/change-password'
    fill_in 'Password', :with=>'apple'
    fill_in 'Confirm Password', :with=>'apple'
    click_button 'Change Password'
    page.html.must_match(/invalid password, does not meet requirements/)
    page.find('#error_flash').text.must_equal "There was an error changing your password"
    page.current_path.must_equal '/change-password'

    fill_in 'Password', :with=>'my_banana_3'
    fill_in 'Confirm Password', :with=>'my_banana_3'
    click_button 'Change Password'
    page.current_path.must_equal '/'
  end

  it "should support autologin after account creation" do
    rodauth do
      enable :login, :create_account
      create_account_autologin? true
    end
    roda do |r|
      r.rodauth
      next unless session[:account_id]
      r.root{view :content=>"Logged In: #{Account[session[:account_id]].email}"}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo2@example.com'
    fill_in 'Confirm Login', :with=>'foo2@example.com'
    fill_in 'Password', :with=>'apple2'
    fill_in 'Confirm Password', :with=>'apple2'
    click_button 'Create Account'
    page.html.must_match(/Logged In: foo2@example\.com/)
  end

  it "should require login to perform certain actions" do
    rodauth do
      enable :login, :change_password, :change_login, :close_account
    end
    roda do |r|
      r.rodauth

      r.is "a" do
        rodauth.require_login
      end
    end

    visit '/change-password'
    page.current_path.must_equal '/login'

    visit '/change-login'
    page.current_path.must_equal '/login'

    visit '/close-account'
    page.current_path.must_equal '/login'

    visit '/a'
    page.current_path.must_equal '/login'
  end

  it "should handle cases where you are already logged in on pages that don't expect a login" do
    rodauth do
      enable :login, :logout, :create_account, :reset_password, :verify_account
      already_logged_in{request.redirect '/'}
    end
    roda do |r|
      r.rodauth

      r.root do
        view :content=>''
      end
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'

    visit '/login'
    page.current_path.must_equal '/'

    visit '/create-account'
    page.current_path.must_equal '/'

    visit '/reset-password'
    page.current_path.must_equal '/'

    visit '/verify-account'
    page.current_path.must_equal '/'

    visit '/logout'
    page.current_path.must_equal '/logout'
  end

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
    link = Mail::TestMailer.deliveries.first.body.to_s[/(\/reset-password\?key=.+)$/]
    Mail::TestMailer.deliveries.clear
    link.must_be_kind_of(String)

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

  it "should support verifying accounts" do
    rodauth do
      enable :login, :create_account, :verify_account
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Confirm Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    fill_in 'Confirm Password', :with=>'0123456789'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    page.current_path.must_equal '/'

    link = Mail::TestMailer.deliveries.first.body.to_s[/(\/verify-account\?key=.+)$/]
    Mail::TestMailer.deliveries.clear

    visit '/login'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.find('#error_flash').text.must_equal 'The account you tried to login with is currently awaiting verification'
    page.html.must_match(/If you no longer have the email to verify the account, you can request that it be resent to you/)
    click_button 'Send Verification Email Again'
    page.current_path.must_equal '/login'

    Mail::TestMailer.deliveries.first.body.to_s[/(\/verify-account\?key=.+)$/].must_equal link
    Mail::TestMailer.deliveries.clear

    visit '/create-account'
    fill_in 'Login', :with=>'foo@example2.com'
    click_button 'Create Account'
    click_button 'Send Verification Email Again'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    page.current_path.must_equal '/login'

    link = Mail::TestMailer.deliveries.first.body.to_s[/(\/verify-account\?key=.+)$/]
    Mail::TestMailer.deliveries.clear

    visit link
    click_button 'Verify Account'
    page.find('#notice_flash').text.must_equal "Your account has been verified"
    page.current_path.must_equal '/'

    visit '/login'
    fill_in 'Login', :with=>'foo@example2.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.current_path.must_equal '/'
  end

  it "should support login via remember token" do
    rodauth do
      enable :login, :remember
    end
    roda do |r|
      r.rodauth
      r.get 'load' do
        rodauth.load_memory
        r.redirect '/'
      end
      r.root{rodauth.logged_in? ? "Logged In#{session[:remembered]}" : "Not Logged In"}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.body.must_equal 'Logged In'

    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    page.body.must_equal 'Logged In'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_equal 'Not Logged In'

    visit '/load'
    page.body.must_equal 'Logged Intrue'

    key = get_cookie('_remember')
    visit '/remember'
    choose 'Forget Me'
    click_button 'Change Remember Setting'
    page.body.must_equal 'Logged Intrue'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_equal 'Not Logged In'

    visit '/load'
    page.body.must_equal 'Not Logged In'

    set_cookie('_remember', key)
    visit '/load'
    page.body.must_equal 'Logged Intrue'

    visit '/remember'
    choose 'Disable Remember Me'
    click_button 'Change Remember Setting'
    page.body.must_equal 'Logged Intrue'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_equal 'Not Logged In'

    set_cookie('_remember', key)
    visit '/load'
    page.body.must_equal 'Not Logged In'
  end

  it "should forget remember token when explicitly logging out" do
    rodauth do
      enable :login, :logout, :remember
    end
    roda do |r|
      r.rodauth
      r.get 'load' do
        rodauth.load_memory
        r.redirect '/'
      end
      r.root{rodauth.logged_in? ? "Logged In#{session[:remembered]}" : "Not Logged In"}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.body.must_equal 'Logged In'

    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    page.body.must_equal 'Logged In'

    visit '/logout'
    click_button 'Logout'

    visit '/'
    page.body.must_equal 'Not Logged In'

    visit '/load'
    page.body.must_equal 'Not Logged In'
  end

  it "should support clearing remembered flag" do
    rodauth do
      enable :login, :remember
    end
    roda do |r|
      r.rodauth
      r.get 'load' do
        rodauth.load_memory
        r.redirect '/'
      end
      r.root{rodauth.logged_in? ? "Logged In#{session[:remembered]}" : "Not Logged In"}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.body.must_equal 'Logged In'

    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    page.body.must_equal 'Logged In'

    remove_cookie('rack.session')
    visit '/'
    page.body.must_equal 'Not Logged In'

    visit '/load'
    page.body.must_equal 'Logged Intrue'

    visit '/remember?confirm=t'
    fill_in 'Password', :with=>'012345678'
    click_button 'Confirm Password'
    page.html.must_match(/invalid password/)

    fill_in 'Password', :with=>'0123456789'
    click_button 'Confirm Password'
    page.body.must_equal 'Logged In'
  end

  it "should support account lockouts" do
    rodauth do
      enable :lockout
      max_invalid_logins 2
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>(rodauth.logged_in? ? "Logged In" : "Not Logged")}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'012345678910'
    click_button 'Login'
    page.find('#error_flash').text.must_equal 'There was an error logging in'

    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.body.must_match(/Logged In/)

    remove_cookie('rack.session')

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    3.times do
      fill_in 'Password', :with=>'012345678910'
      click_button 'Login'
      page.find('#error_flash').text.must_equal 'There was an error logging in'
    end
    page.body.must_match(/This account is currently locked out/)
    click_button 'Request Account Unlock'
    page.find('#notice_flash').text.must_equal 'An email has been sent to you with a link to unlock your account'

    link = Mail::TestMailer.deliveries.first.body.to_s[/(\/unlock-account\?key=.+)$/]
    Mail::TestMailer.deliveries.clear
    link.must_be_kind_of(String)

    visit link
    click_button 'Unlock Account'
    page.find('#notice_flash').text.must_equal 'Your account has been unlocked'

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.body.must_match(/Logged In/)
  end
end
