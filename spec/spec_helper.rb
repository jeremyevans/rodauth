$: << 'lib'

if ENV['WARNING']
  require 'warning'
  Warning.ignore([:missing_ivar, :missing_gvar, :fixnum])
  #Warning.ignore(/warning: URI\.escape is obsolete\n\z/)
  Warning.ignore(:method_redefined, File.dirname(File.dirname(__FILE__)))
end

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
require 'stringio'
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
DB = Sequel.connect(db_url, :identifier_mangling=>false)
DB.extension(:freeze_datasets)
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

Base = Class.new(Roda)
Base.plugin :render, :layout_opts=>{:path=>'spec/views/layout.str'}
Base.plugin(:not_found){raise "path #{request.path_info} not found"}
Base.use Rack::Session::Cookie, :secret=>'0123456789'
class Base
  attr_writer :title
end

JsonBase = Class.new(Roda)
JsonBase.plugin(:not_found){raise "path #{request.path_info} not found"}

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

  def roda(type=nil, &block)
    jwt_only = type == :jwt
    jwt = type == :jwt || type == :jwt_html

    app = Class.new(jwt_only ? JsonBase : Base)
    rodauth_block = @rodauth_block
    opts = type.is_a?(Hash) ? type : {}

    if jwt
      opts[:json] = jwt_only ? :only : true
    end

    app.plugin(:rodauth, opts) do
      title_instance_variable :@title
      if jwt
        enable :jwt
        jwt_secret '1'
        json_response_success_key 'success'
        json_response_custom_error_status? true
      end
      instance_exec(&rodauth_block)
    end
    app.route(&block)
    app.freeze unless @no_freeze
    self.app = app
  end

  def email_link(regexp, to='foo@example.com')
    msgs = Mail::TestMailer.deliveries
    msgs.length.must_equal 1
    msgs.first.to.first.must_equal to

    link = msgs.first.body.to_s[regexp]
    msgs.clear
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

  def json_request(path='/', params={})
    include_headers = params.delete(:include_headers)
    headers = params.delete(:headers)

    env = {"REQUEST_METHOD" => params.delete(:method) || "POST",
           "PATH_INFO" => path,
           "SCRIPT_NAME" => "",
           "CONTENT_TYPE" => params.delete(:content_type) || "application/json",
           "SERVER_NAME" => 'example.com',
           "rack.input"=>StringIO.new((params || {}).to_json)
    }

    if @authorization
      env["HTTP_AUTHORIZATION"] = "Bearer: #{@authorization}"
    end
    if @cookie
      env["HTTP_COOKIE"] = @cookie
    end

    env.merge!(headers) if headers

    r = @app.call(env)

    if cookie = r[1]['Set-Cookie']
      @cookie = cookie
    end
    if authorization = r[1]['Authorization']
      @authorization = authorization
    end

    if env["CONTENT_TYPE"] == "application/json"
      r[1]['Content-Type'].must_equal 'application/json'
      r[2] = JSON.parse("[#{r[2].join}]").first
    end

    r.delete_at(1) unless include_headers
    r
  end

  def json_login(opts={})
    res = json_request(opts[:path]||'/login', :login=>opts[:login]||'foo@example.com', :password=>opts[:pass]||'0123456789')
    res.must_equal [200, {"success"=>'You have been logged in'}] unless opts[:no_check]
    res
  end

  def json_logout
    json_request("/logout").must_equal [200, {"success"=>'You have been logged out'}]
  end

  def login(opts={})
    visit(opts[:path]||'/login') unless opts[:visit] == false
    fill_in 'Login', :with=>opts[:login]||'foo@example.com'
    fill_in 'Password', :with=>opts[:pass]||'0123456789'
    click_button 'Login'
  end

  def logout
    visit '/logout'
    click_button 'Logout'
  end

  around do |&block|
    DB.transaction(:rollback=>:always, :savepoint=>true, :auto_savepoint=>true){super(&block)}
  end
  
  around(:all) do |&block|
    DB.transaction(:rollback=>:always) do
      hash = BCrypt::Password.create('0123456789', :cost=>BCrypt::Engine::MIN_COST)
      DB[:account_password_hashes].insert(:id=>DB[:accounts].insert(:email=>'foo@example.com', :status_id=>2, :ph=>hash), :password_hash=>hash)
      super(&block)
    end
  end
  
  after do
    msgs = Mail::TestMailer.deliveries
    len = msgs.length
    msgs.clear
    len.must_equal 0
    Capybara.reset_sessions!
    Capybara.use_default_driver
  end
end


