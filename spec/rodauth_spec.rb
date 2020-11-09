require_relative 'spec_helper'

describe 'Rodauth' do
  it "should keep private methods private when overridden" do
    rodauth do
      use_database_authentication_functions? false
    end
    roda do |r|
      rodauth.use_database_authentication_functions?.to_s
    end

    proc{visit '/'}.must_raise NoMethodError
  end

  it "should support template_opts" do
    rodauth do
      enable :login
      template_opts(:layout_opts=>{:path=>'spec/views/layout-other.str'})
    end
    roda do |r|
      r.rodauth
    end

    visit '/login'
    page.title.must_equal 'Foo Login'
  end

  it "should support flash_error_key and flash_notice_key" do
    rodauth do
      enable :login
      template_opts(:layout_opts=>{:path=>'spec/views/layout-other.str'})
      flash_error_key 'error2'
      flash_notice_key 'notice2'
    end
    roda do |r|
      r.rodauth
      rodauth.require_login
      view(:content=>'', :layout_opts=>{:path=>'spec/views/layout-other.str'})
    end

    visit '/'
    page.html.must_include 'Please login to continue'
    login(:visit=>false)
    page.html.must_include 'You have been logged in'
  end

  it "should support customizing titles for views" do
    rodauth do
      enable :login, :reset_password
      login_page_title 'FooLogin'
      reset_password_request_page_title 'FooRP'
    end
    roda do |r|
      r.rodauth
    end

    visit '/login'
    page.title.must_equal 'FooLogin'
    visit '/reset-password-request'
    page.title.must_equal 'FooRP'
  end

  it "should support loading rodauth plugin twice in same class" do
    @no_freeze = true
    rodauth do
      enable :login
      login_page_title 'FooLogin'
    end
    roda do |r|
      r.rodauth
    end
    @app.plugin :rodauth do
      enable :reset_password
      reset_password_request_page_title 'FooRP'
    end

    visit '/login'
    page.title.must_equal 'FooLogin'
    visit '/reset-password-request'
    page.title.must_equal 'FooRP'
  end

  it "should support route paths and URLs with prefix and query parameters" do
    block = proc{''}
    prefix = ''

    rodauth do
      enable :login
      prefix { prefix }
    end
    roda do |r|
      view :content=>instance_exec(&block)
    end

    block = proc{rodauth.login_path}
    visit '/'
    page.text.must_equal '/login'

    prefix = '/auth'
    visit '/'
    page.text.must_equal '/auth/login'

    block = proc{rodauth.login_path(a: 'b c')}
    visit '/'
    page.text.must_equal '/auth/login?a=b+c'

    block = proc{rodauth.login_path(a: 'b', c: 'd')}
    visit '/'
    page.text.must_equal '/auth/login?a=b&c=d'

    block = proc{rodauth.login_path(a: ['b', 'c'])}
    visit '/'
    page.text.must_equal '/auth/login?a[]=b&a[]=c'

    block = proc{rodauth.login_url}
    prefix = ''
    visit '/'
    page.text.must_equal 'http://www.example.com/login'

    prefix = '/auth'
    visit '/'
    page.text.must_equal 'http://www.example.com/auth/login'

    block = proc{rodauth.login_url(a: 'b c')}
    visit '/'
    page.text.must_equal 'http://www.example.com/auth/login?a=b+c'

    block = proc{rodauth.login_url(a: 'b', c: 'd')}
    visit '/'
    page.text.must_equal 'http://www.example.com/auth/login?a=b&c=d'

    block = proc{rodauth.login_url(a: ['b', 'c'])}
    visit '/'
    page.text.must_equal 'http://www.example.com/auth/login?a[]=b&a[]=c'
  end

  it "should support session key prefix" do
    rodauth do
      session_key_prefix "prefix_"
    end
    roda do |r|
      r.root { rodauth.session_key.inspect }
    end

    visit '/'

    if app.opts[:sessions_convert_symbols]
      page.html.must_equal "\"prefix_account_id\""
    else
      page.html.must_equal ":prefix_account_id"
    end
  end

  it "should support translation" do
    rodauth do
      enable :login
      translate do |key, value|
        "#{key}-#{value}"
      end
    end
    roda do |r|
      r.rodauth
      view :content=>''
    end

    visit '/login'
    page.title.must_equal 'login_page_title-Login'
    fill_in "login_label-Login", :with=>'foo@example.com'
    fill_in "password_label-Password", :with=>'0123456789'
    click_button 'login_button-Login'
    page.current_path.must_equal '/'
    page.find('#notice_flash').text.must_equal 'login_notice_flash-You have been logged in'
  end

  it "should work without preloading the templates" do
    @no_precompile = true
    rodauth do
      enable :login
    end
    roda do |r|
      r.rodauth
    end

    visit '/login'
    page.title.must_equal 'Login'
  end

  it "should warn when using deprecated configuration methods" do
    warning = nil
    rodauth do
      enable :email_auth
      define_singleton_method(:warn) do |*a|
        warning = a.first
      end
      auth_class_eval do
        define_method(:warn) do |*a|
          warning = a.first
        end
        private :warn
      end
      Rodauth::EmailAuth.send(:def_deprecated_alias, :no_matching_email_auth_key_error_flash, :no_matching_email_auth_key_message)
      no_matching_email_auth_key_message 'foo'
    end
    roda do |r|
      rodauth.no_matching_email_auth_key_message
    end

    warning.must_equal "Deprecated no_matching_email_auth_key_message method used during configuration, switch to using no_matching_email_auth_key_error_flash"
    visit '/'
    body.must_equal 'foo'
    warning.must_equal "Deprecated no_matching_email_auth_key_message method called at runtime, switch to using no_matching_email_auth_key_error_flash"
  end

  it "should pick up template changes if not caching templates" do
    begin
      @no_freeze = true
      cache = true
      rodauth do
        enable :login
        cache_templates{cache}
      end
      roda do |r|
        r.rodauth
      end
      dir = 'spec/views2'
      file = "#{dir}/login.str"
      app.plugin :render, :views=>dir, :engine=>'str'
      Dir.mkdir(dir) unless File.directory?(dir)

      text = File.read('spec/views/login.str')
      File.open(file, 'wb'){|f| f.write text}
      visit '/login'
      page.all('label').first.text.must_equal 'Login'

      File.open(file, 'wb'){|f| f.write text.gsub('Login', 'Banana')}
      visit '/login'
      page.all('label').first.text.must_equal 'Login'

      cache = false
      visit '/login'
      page.all('label').first.text.must_equal 'Banana'
    ensure
      File.delete(file) if File.file?(file)
      Dir.rmdir(dir) if File.directory?(dir)
    end
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

  it "should handle case where account is no longer valid during session" do
    rodauth do
      enable :login, :change_password
      already_logged_in{request.redirect '/'}
      skip_status_checks? false
    end
    roda do |r|
      r.rodauth

      r.root do
        view :content=>(rodauth.logged_in? ? "Logged In" : "Not Logged")
      end
    end

    login
    page.body.must_include("Logged In")

    DB[:accounts].update(:status_id=>3)
    visit '/change-password'
    page.current_path.must_equal '/login'
    visit '/'
    page.body.must_include("Not Logged")
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

    login

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

  it "should have rodauth.features and rodauth.session_value work when not logged in" do
    rodauth do
      enable :login
    end
    roda do |r|
      "#{rodauth.features.first.inspect}#{rodauth.session_value.inspect}"
    end

    visit '/'
    page.body.must_equal ':loginnil'
  end

  it "should support auth_class_eval for evaluation inside Auth class" do
    rodauth do
      enable :login
      login_label{foo}
      auth_class_eval do
        def foo
          'Lonig'
        end
      end
    end
    roda do |r|
      r.rodauth
    end

    visit '/login'
    fill_in 'Lonig', :with=>'foo@example.com'
  end

  it "should support multiple rodauth configurations in an app" do
    app = Class.new(Base)
    app.plugin(:rodauth, rodauth_opts) do
      enable :login
      if ENV['RODAUTH_SEPARATE_SCHEMA']
        password_hash_table Sequel[:rodauth_test_password][:account_password_hashes]
        function_name do |name|
          "rodauth_test_password.#{name}"
        end
      end
    end
    app.plugin(:rodauth, rodauth_opts.merge(:name=>:r2)) do
      enable :logout
    end

    if Minitest::HooksSpec::USE_ROUTE_CSRF
      app.plugin :route_csrf, Minitest::HooksSpec::ROUTE_CSRF_OPTS
    end

    app.route do |r|
      if Minitest::HooksSpec::USE_ROUTE_CSRF
        check_csrf!
      end
      r.on 'r1' do
        r.rodauth
        'r1'
      end
      r.on 'r2' do
        r.rodauth(:r2)
        'r2'
      end
      rodauth.session_value.inspect
    end
    app.freeze
    self.app = app

    login(:path=>'/r1/login')
    page.body.must_equal DB[:accounts].get(:id).inspect

    visit '/r2/logout'
    click_button 'Logout'
    page.body.must_equal 'nil'

    visit '/r1/logout'
    page.body.must_equal 'r1'
    visit '/r2/login'
    page.body.must_equal 'r2'
  end

  it "should support account_select setting for choosing account columns" do
    rodauth do
      enable :login
      account_select [:id, :email]
    end
    roda do |r|
      r.rodauth
      rodauth.account_from_session
      rodauth.account.keys.map(&:to_s).sort.join(' ')
    end

    login
    page.body.must_equal 'email id'
  end

  it "should support :csrf=>false and :flash=>false plugin options" do
    c = Class.new(Roda)
    c.plugin(:rodauth, :csrf=>false, :flash=>false){}
    c.route{}
    c.instance_variable_get(:@middleware).length.must_equal 0
    c.ancestors.map(&:to_s).wont_include 'Roda::RodaPlugins::Flash::InstanceMethods'
    c.ancestors.map(&:to_s).wont_include 'Roda::RodaPlugins::RouteCsrf::InstanceMethods'
  end

  it "should inherit rodauth configuration in subclass" do
    auth_class = nil
    no_freeze!
    rodauth{auth_class = auth}
    roda(:csrf=>false, :flash=>false){|r|}
    Class.new(app).rodauth.must_equal auth_class
  end

  it "should use subclass of rodauth configuration if modifying rodauth configuration in subclass" do
    auth_class = nil
    no_freeze!
    rodauth{auth_class = auth; auth_class_eval{def foo; 'foo' end}}
    roda{|r| rodauth.foo}
    visit '/'
    page.html.must_equal 'foo'

    a = Class.new(app)
    a.plugin(:rodauth, rodauth_opts){auth_class_eval{def foo; "#{super}bar" end}}
    a.rodauth.superclass.must_equal auth_class

    visit '/'
    page.html.must_equal 'foo'
    self.app = a
    visit '/'
    page.html.must_equal 'foobar'
  end

  it "should work when not using CSRF or bcrypt" do
    rodauth do
      enable :login
      require_bcrypt? false
      account_password_hash_column :foo
    end
    roda(:no_csrf) do |r|
      r.rodauth
    end

    login
    page.find('#error_flash').text.must_equal 'There was an error logging in'
    page.html.must_include("invalid password")
  end

  it "should use correct values for some internal methods" do
    auth = nil
    rodauth do
      enable :login
      template_opts(:locals=>{a: 1})
    end
    roda(:no_csrf) do |r|
      r.rodauth
      auth = rodauth
      view :content=>"Possible Authentication Methods: #{rodauth.possible_authentication_methods.join(' ')}."
    end

    visit '/'
    page.html.must_include("Possible Authentication Methods: .")
    proc{auth.send(:account_ds, nil)}.must_raise ArgumentError
    
    login
    page.html.must_include("Possible Authentication Methods: password.")
    auth.send(:password_hash_ds).get(:id).must_be_kind_of(ENV['RODAUTH_SPEC_UUID'] && DB.database_type == :postgres ? String : Integer)
    auth.send(:convert_timestamp, "2020-10-12 12:00:00").strftime('%Y-%m-%d').must_equal '2020-10-12'
  end

  it "should run route hooks" do
    hooks = []
    rodauth do
      enable :login
      before_rodauth do
        hooks << :before
      end
      around_rodauth do |&block|
        begin
          hooks << :before_around
          super(&block)
        ensure
          hooks << :after_around
        end
      end
    end
    roda do |r|
      r.rodauth
    end
    visit '/login'
    hooks.must_equal [:before_around, :before, :after_around]
  end
end
