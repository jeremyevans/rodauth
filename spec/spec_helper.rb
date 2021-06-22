$: << 'lib'

begin
  # Needed for Ruby 2.3 and webauthn, which requires openssl gem > 2
  gem "openssl", '>2' if RUBY_VERSION < '2.4'
rescue LoadError
end

if ENV['WARNING']
  require 'warning'
  Warning.ignore([:missing_ivar, :missing_gvar, :fixnum, :not_reached])
  Warning.dedup if Warning.respond_to?(:dedup)
end

if ENV['COVERAGE']
  require 'coverage'
  require 'simplecov'

  def SimpleCov.rodauth_coverage(opts = {})
    start do
      enable_coverage :branch

      # Work around Ruby Bug #16967
      Coverage.singleton_class.prepend(Module.new do
        def result
          res = super
          check_branch = true
          skip_2nd = lambda do |ary|
            ary = ary.dup
            ary.slice!(1)
            ary
          end
          res.values.each do |hash|
            if check_branch
              unless hash.is_a?(Hash) && hash[:branches]
                return res
              end
              check_branch = false
            end
            unique_branches = {}
            branch_counters = {}
            new_branches = {}
            branches = hash[:branches]
            branches.each do |k, v|
              new_k = skip_2nd[k]
              if branch_values = unique_branches[new_k]
                v.each do |k1, v1|
                  branch_counters[skip_2nd[k1]] += v1
                end
                branch_values.keys.each do |k1|
                  branch_values[k1] = branch_counters[skip_2nd[k1]]
                end
              else
                unique_branches[new_k] = new_branches[k] = v
                v.each do |k1, v1|
                  branch_counters[skip_2nd[k1]] = v1
                end
              end
            end
            hash[:branches] = new_branches
          end
          res
        end
      end)
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
require 'securerandom'

ENV['MT_NO_PLUGINS'] = '1' # Work around stupid autoloading of plugins
gem 'minitest'
require 'minitest/global_expectations/autorun'
require 'minitest/hooks/default'

if ENV['CHECK_METHOD_VISIBILITY']
  require 'visibility_checker'
  VISIBILITY_CHANGES = []
  Minitest.after_run do
    if VISIBILITY_CHANGES.empty?
      puts "No visibility changes"
    else
      puts "Visibility changes:"
      VISIBILITY_CHANGES.uniq!{|v,| v}
      puts(*VISIBILITY_CHANGES.map do |v, caller|
        "#{caller}: #{v.new_visibility} method #{v.overridden_by}##{v.method} overrides #{v.original_visibility} method in #{v.defined_in}"
      end.sort)
    end
  end
end

require 'roda'
require 'sequel'
require 'bcrypt'
require 'mail'
require 'logger'
require 'tilt/string'

unless db_url = ENV['RODAUTH_SPEC_DB']
  db_url = if RUBY_ENGINE == 'jruby'
    'jdbc:postgresql:///rodauth_test?user=rodauth_test&password=rodauth_test'
  else
    'postgres:///?user=rodauth_test&password=rodauth_test'
  end
end
DB = Sequel.connect(db_url, :identifier_mangling=>false)
DB.extension :freeze_datasets, :date_arithmetic
puts "using #{DB.database_type}"

DB.loggers << Logger.new($stdout) if ENV['LOG_SQL']
if DB.adapter_scheme == :jdbc
  case DB.database_type
  when :postgres
    DB.add_named_conversion_proc(:citext){|s| s}
    DB.extension :pg_json # jsonb usage in audit_logging
  when :sqlite
    DB.timezone = :utc
    Sequel.application_timezone = :local
  end
end

if ENV['RODAUTH_SPEC_MIGRATE']
  Sequel.extension :migration
  Sequel::Migrator.run(DB, 'spec/migrate_ci')
end

DB.freeze

ENV['RACK_ENV'] = 'test'

::Mail.defaults do
  delivery_method :test
end

Base = Class.new(Roda)
Base.opts[:check_dynamic_arity] = Base.opts[:check_arity] = :warn
Base.plugin :flash
Base.plugin :render, :layout_opts=>{:path=>'spec/views/layout.str'}
Base.plugin(:not_found){raise "path #{request.path_info} not found"}

if defined?(Roda::RodaVersionNumber) && Roda::RodaVersionNumber >= 30100
  if ENV['SESSIONS'] == 'middleware'
    require 'roda/session_middleware'
    Base.opts[:sessions_convert_symbols] = true
    Base.use RodaSessionMiddleware, :secret=>SecureRandom.random_bytes(64), :key=>'rack.session'
  elsif ENV['SESSIONS'] != 'rack'
    Base.plugin :sessions, :secret=>SecureRandom.random_bytes(64), :key=>'rack.session'
  end
end

if ENV['SESSIONS'] == 'rack'
  Base.use Rack::Session::Cookie, :secret => '0123456789'
end

unless defined?(Rack::Test::VERSION) && Rack::Test::VERSION >= '0.8'
  class Rack::Test::Cookie
    def path
      ([*(@options['path'] == "" ? "/" : @options['path'])].first.split(',').first || '/').strip
    end
  end
end

class Base
  attr_writer :title
end

JsonBase = Class.new(Roda)
JsonBase.opts[:check_dynamic_arity] = JsonBase.opts[:check_arity] = :warn
JsonBase.plugin(:not_found){raise "path #{request.path_info} not found"}

RODAUTH_ALWAYS_ARGON2 = ENV['RODAUTH_ALWAYS_ARGON2'] == '1'
require 'argon2' if RODAUTH_ALWAYS_ARGON2

class Minitest::HooksSpec
  include Rack::Test::Methods
  include Capybara::DSL
  
  case ENV['RODA_ROUTE_CSRF']
  when 'no'
    USE_ROUTE_CSRF = false
  when 'no-specific'
    USE_ROUTE_CSRF = true
    ROUTE_CSRF_OPTS = {:require_request_specific_tokens=>false, :check_header=>true}
  when 'always'
    USE_ROUTE_CSRF = :always
    ROUTE_CSRF_OPTS = {:check_header=>true}
  else
    USE_ROUTE_CSRF = true
    ROUTE_CSRF_OPTS = {:check_header=>true}
  end

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

  def rodauth_opts(type={})
    opts = type.is_a?(Hash) ? type : {}
    if !USE_ROUTE_CSRF && !opts.has_key?(:csrf)
      opts[:csrf] = :rack_csrf
    end
    opts
  end

  def apply_csrf(app, opts)
    case opts[:csrf]
    when :rack_csrf
      app.plugin(:csrf, :raise => true, :skip_if=>lambda{|request| @jwt_type && request.env["CONTENT_TYPE"] == "application/json"})
    when false
      # nothing
    else
      app.plugin(:route_csrf, ROUTE_CSRF_OPTS) if USE_ROUTE_CSRF
    end
  end

  def roda(type=nil, &block)
    jwt_only = type == :jwt || type == :jwt_no_enable
    jwt = @jwt_type = type == :jwt || type == :jwt_html || type == :jwt_no_enable
    jwt_enable = type == :jwt || type == :jwt_html
    json_only = type == :json || type == :json_no_enable
    json = type == :json || type == :json_html || type == :json_no_enable
    json_enable = type == :json || type == :json_html

    app = Class.new(jwt_only ? JsonBase : Base)
    begin
      app.plugin :request_aref, :raise
    rescue LoadError
    end
    app.opts[:unsupported_block_result] = :raise
    app.opts[:unsupported_matcher] = :raise
    app.opts[:verbatim_string_matcher] = true
    rodauth_block = @rodauth_block
    opts = rodauth_opts(type)

    if json || jwt
      opts[:json] = jwt_only ? :only : true
    end

    if type == :no_csrf
      opts[:csrf] = false
    end

    app.plugin(:rodauth, opts) do
      title_instance_variable :@title
      if jwt_enable
        enable :jwt
        jwt_secret '1'
      end
      if json_enable
        enable :json
        only_json? true if json_only
      end
      if jwt_enable || json_enable
        set_error_reason { |reason| json_response['reason'] = reason }
      end
      if ENV['RODAUTH_SEPARATE_SCHEMA']
        password_hash_table Sequel[:rodauth_test_password][:account_password_hashes]
        function_name do |name|
          "rodauth_test_password.#{name}"
        end
      end
      if RODAUTH_ALWAYS_ARGON2
        enable :argon2
      end
      instance_exec(&rodauth_block)
    end
    unless jwt_only
      apply_csrf(app, opts)
    end
    if USE_ROUTE_CSRF == :always && !jwt && opts[:csrf] != false
      orig_block = block
      block = proc do |r|
        check_csrf!
        instance_exec(r, &orig_block)
      end
    end
    app.route(&block)
    app.precompile_rodauth_templates unless @no_precompile || jwt_only
    app.freeze unless @no_freeze
    if ENV['CHECK_METHOD_VISIBILITY']
      caller = caller_locations(1, 1)[0]
      app.opts[:rodauths].each_value do |c|
        VISIBILITY_CHANGES.concat(VisibilityChecker.visibility_changes(c).map{|v| [v, "#{caller.path}:#{caller.lineno}"]})
      end
    end
    @app_opts = opts
    self.app = app
  end

  def email_link(regexp, to='foo@example.com')
    msgs = Mail::TestMailer.deliveries
    msgs.length.must_equal 1
    msgs.first.to.first.must_equal to

    link = msgs.first.body.to_s.gsub(/ $/, '')[regexp]
    msgs.clear
    link.must_be_kind_of(String)
    link
  end

  def remove_cookie(key)
    page.driver.browser.rack_mock_session.cookie_jar.delete(key)
  end

  def get_cookie(key)
    cookie_jar[key]
  end

  def retrieve_cookie(key)
    yield cookie_jar.get_cookie(key) if cookie_jar.respond_to?(:get_cookie)
  end

  def set_cookie(key, value)
    cookie_jar[key] = value
  end

  def cookie_jar
    page.driver.browser.rack_mock_session.cookie_jar
  end

  def get_csrf(env, *args)
    sc = Class.new(Base)
    apply_csrf(sc, @app_opts)
    
    csrf = nil
    sc.route do |_|
      csrf = csrf_token(*args)
      ''
    end
    method = env['REQUEST_METHOD']
    env['REQUEST_METHOD'] = 'GET'
    if @cookie
      env["HTTP_COOKIE"] = @cookie.map { |k, v| "#{k}=#{v}" }.join("; ")
    end
    r = sc.call(env)
    env['REQUEST_METHOD'] = method

    if set_cookie = r[1]['Set-Cookie']
      @cookie ||= {}
      set_cookie.split("\n").each do |cookie|
        cookie_key, cookie_value = cookie.split(';', 2)[0].split("=")
        if cookie.include?('expires=Thu, 01 Jan 1970 00:00:00')
          @cookie.delete(cookie_key)
        else
          @cookie[cookie_key] = cookie_value
        end
      end
      @cookie = nil if @cookie.empty?
    end

    csrf
  end

  def json_request(path='/', params={})
    include_headers = params.delete(:include_headers)
    headers = params.delete(:headers)
    csrf = params.delete(:csrf)

    env = {"REQUEST_METHOD" => params.delete(:method) || "POST",
           "HTTP_HOST" => "example.com",
           "PATH_INFO" => path,
           "SCRIPT_NAME" => "",
           "CONTENT_TYPE" => params.delete(:content_type) || "application/json",
           "SERVER_NAME" => 'example.com',
           "rack.input"=>StringIO.new((params || {}).to_json),
           "rack.errors"=>$stderr,
           "rack.url_scheme"=>"http"
    }

    if @authorization
      env["HTTP_AUTHORIZATION"] = "Bearer: #{@authorization}"
    end

    unless @app.opts[:rodauth_json] == :only || csrf == false || @app_opts[:csrf] == false
      if @app.opts[:rodauth_csrf] == :rack_csrf || ROUTE_CSRF_OPTS[:require_request_specific_tokens] == false
        env["HTTP_X_CSRF_TOKEN"] = get_csrf(env)
      elsif @app.opts[:rodauth_csrf] != false
        env["HTTP_X_CSRF_TOKEN"] = get_csrf(env, path)
      end
    end

    if @cookie
      env["HTTP_COOKIE"] = @cookie.map { |k, v| "#{k}=#{v}" }.join("; ")
    end

    env.merge!(headers) if headers

    r = @app.call(env)

    if set_cookie = r[1]['Set-Cookie']
      @cookie ||= {}
      set_cookie.split("\n").each do |cookie|
        cookie_key, cookie_value = cookie.split(';', 2)[0].split("=")
        if cookie.include?('expires=Thu, 01 Jan 1970 00:00:00')
          @cookie.delete(cookie_key)
        else
          @cookie[cookie_key] = cookie_value
        end
      end
      @cookie = nil if @cookie.empty?
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

  def jwt_refresh_login(opts={})
    res = json_login(opts.merge(:no_check => true))
    jwt_refresh_validate_login(res)
    res
  end

  def jwt_refresh_validate_login(res)
    res.first.must_equal 200
    res.last.keys.sort.must_equal ['access_token', 'refresh_token', 'success']
    res.last['success'].must_equal 'You have been logged in'
    res
  end

  def jwt_refresh_validate(res)
    res.first.must_equal 200
    res.last.keys.sort.must_equal ['access_token', 'refresh_token']
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
      hash = if RODAUTH_ALWAYS_ARGON2
        ::Argon2::Password.new(t_cost: 1, m_cost: 3).create('0123456789')
      else
        BCrypt::Password.create('0123456789', :cost=>BCrypt::Engine::MIN_COST)
      end
      table = ENV['RODAUTH_SEPARATE_SCHEMA'] ? Sequel[:rodauth_test_password][:account_password_hashes] : :account_password_hashes
      DB[table].insert(:id=>DB[:accounts].insert(:email=>'foo@example.com', :status_id=>2, :ph=>hash), :password_hash=>hash)
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
