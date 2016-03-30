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

db_url = ENV['RODAUTH_SPEC_DB'] || 'postgres:///?user=rodauth_test&password=rodauth_test'
DB = Sequel.connect(db_url)
puts "using #{DB.database_type}"

#DB.loggers << Logger.new($stdout)
if DB.adapter_scheme == :jdbc && DB.database_type == :postgres
  DB.add_named_conversion_proc(:citext){|s| s}
end
if DB.adapter_scheme == :jdbc && DB.database_type == :sqlite
  DB.timezone = :utc
  Sequel.application_timezone = :local
end
if ENV['RODAUTH_SPEC_MIGRATE']
  Sequel.extension :migration
  Sequel::Migrator.run(DB, 'spec/migrate_travis')
end

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

  def no_freeze!
    @no_freeze = true
  end

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
    app.freeze unless @no_freeze
    self.app = app
  end

  def email_link(regexp)
    link = Mail::TestMailer.deliveries.first.body.to_s[regexp]
    Mail::TestMailer.deliveries.clear
    link.must_be_kind_of(String)
    link
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
    DB.transaction(:rollback=>:always) do
      hash = BCrypt::Password.create('0123456789', :cost=>BCrypt::Engine::MIN_COST)
      DB[:account_password_hashes].insert(:id=>Account.create(:email=>'foo@example.com', :status_id=>2, :ph=>hash).id, :password_hash=>hash)
      super(&block)
    end
  end
  
  after do
    Capybara.reset_sessions!
    Capybara.use_default_driver
  end
end


