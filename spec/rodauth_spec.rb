$: << 'lib'

require 'rubygems'
require 'capybara'
require 'capybara/dsl'
require 'rack/test'
require 'minitest/autorun'
require 'minitest/hooks/default'

require 'roda'
require 'sequel'
require 'bcrypt'
require 'logger'
require 'tilt/string'

DB = Sequel.postgres(:user=>'rodauth_test')
#DB.loggers << Logger.new($stdout)

class Account < Sequel::Model
  def set_password(password)
    hash = BCrypt::Password.create(password, :cost=>BCrypt::Engine::MIN_COST)
    if DB[:account_password_hashes].where(:id=>id).update(:password_hash=>hash) == 0
      DB[:account_password_hashes].insert(:id=>id, :password_hash=>hash)
    end
  end
end

Base = Class.new(Roda)
Base.plugin :render, :layout=>false
Base.plugin(:not_found){raise "path #{request.path_info} not found"}
Base.use Rack::Session::Cookie, :secret=>'0123456789'

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
    app.plugin(:rodauth, &@rodauth_block)
    app.route(&block)
    self.app = app
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
    Account.create(:email=>'foo@example.com').set_password('0123456789')
  end

  it "should handle logins" do
    rodauth{enable :login}
    roda do |r|
      r.rodauth
      next unless session[:account_id]
      r.root{"Logged In"}
    end

    visit '/login'

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
    page.current_path.must_equal '/'
    page.html.must_match(/Logged In/)
  end
end
