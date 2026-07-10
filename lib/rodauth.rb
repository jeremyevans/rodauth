# frozen-string-literal: true

require 'securerandom'

module Rodauth
  OPTS = {}.freeze
  SCOPE_INSTANCE_VARIABLES = [:@_rodauths, :@_rodauth].freeze

  class ConfigurationError < StandardError; end

  def self.lib(opts=OPTS, &block) 
    require 'roda'
    c = Class.new(Roda)
    c.plugin(:rodauth, opts) do
      enable :internal_request
      instance_exec(&block)
    end
    c.freeze
    c.rodauth
  end

  def self.load_dependencies(app, opts=OPTS, &_)
    json_opt = opts.fetch(:json, app.opts[:rodauth_json])
    if json_opt
      app.plugin :json
      app.plugin :json_parser
    end

    unless json_opt == :only
      unless opts[:render] == false
        require 'tilt/string'
        app.plugin :render
      end

      case opts.fetch(:csrf, app.opts[:rodauth_csrf])
      when false
        # nothing
      when :rack_csrf
        # :nocov:
        app.plugin :csrf
        # :nocov:
      else
        app.plugin :route_csrf
      end

      app.plugin :flash unless opts[:flash] == false
      app.plugin :h
    end
  end

  def self.configure(app, opts=OPTS, &block)
    json_opt = app.opts[:rodauth_json] = opts.fetch(:json, app.opts[:rodauth_json])
    csrf = app.opts[:rodauth_csrf] = opts.fetch(:csrf, app.opts[:rodauth_csrf])
    app.opts[:rodauth_route_csrf] = case csrf
    when false, :rack_csrf
      false
    else
      json_opt != :only
    end
    auth_class = (app.opts[:rodauths] ||= {})[opts[:name]] ||= opts[:auth_class] || Class.new(Auth)
    if !auth_class.roda_class
      auth_class.roda_class = app
    elsif auth_class.roda_class != app
      auth_class = app.opts[:rodauths][opts[:name]] = Class.new(auth_class)
      auth_class.roda_class = app
    end
    auth_class.class_eval{@configuration_name = opts[:name] unless defined?(@configuration_name)}
    auth_class.configure(&block) if block
    auth_class.send(:make_shape_friendly)
    auth_class.allocate.post_configure if auth_class.method_defined?(:post_configure)
  end

  FEATURES = {}

  class FeatureConfiguration < Module
    def def_configuration_methods(feature)
      private_methods = feature.private_instance_methods
      priv = proc{|m| private_methods.include?(m)}
      feature.auth_methods.each do |m|
        _check_method_defined(feature, m, priv[m])
        def_auth_method(m, priv[m])
      end
      feature.auth_value_methods.each do |m|
        _check_method_defined(feature, m, priv[m])
        def_auth_value_method(m, priv[m])
      end
      feature.auth_private_methods.each do |m|
        _check_method_defined(feature, :"_#{m}", true)
        def_auth_private_method(m)
      end
    end

    private

    def _check_method_defined(feature, meth, priv)
      if !feature.send(priv ? :private_method_defined? : :method_defined?, meth) &&
          (!(allowed = feature.allowed_undefined_configuration_methods) || !allowed.include?(meth))
        # RODAUTH3: raise instead of warn
        warn "Bug in Rodauth #{feature.feature_name} feature definition, configuration method added for #{meth}, but the feature doesn't define the method"
      end
    end

    def def_auth_method(meth, priv)
      define_method(meth) do |&block|
        @auth.send(:define_method, meth, &block)
        @auth.send(:private, meth) if priv
        @auth.send(:alias_method, meth, meth)
      end
    end

    def def_auth_private_method(meth)
      umeth = :"_#{meth}"
      define_method(meth) do |&block|
        @auth.send(:define_method, umeth, &block)
        @auth.send(:private, umeth)
        @auth.send(:alias_method, umeth, umeth)
      end
    end

    def def_auth_value_method(meth, priv)
      define_method(meth) do |v=nil, &block|
        block ||= proc{v}
        @auth.send(:define_method, meth, &block)
        @auth.send(:private, meth) if priv
        @auth.send(:alias_method, meth, meth)
      end
    end
  end

  class Feature < Module
    [:auth, :auth_value, :auth_private].each do |meth|
      name = :"#{meth}_methods"
      define_method(name) do |*v|
        iv = :"@#{name}"
        existing = instance_variable_get(iv) || []
        if v.empty?
          existing
        else
          instance_variable_set(iv, existing + v)
        end
      end
    end

    attr_accessor :feature_name
    attr_accessor :dependencies
    attr_accessor :routes
    attr_accessor :configuration
    attr_accessor :allowed_undefined_configuration_methods
    attr_reader :internal_request_methods
    attr_reader :instance_variables_used

    def route(name=feature_name, default=name.to_s.tr('_', '-'), &block)
      route_meth = :"#{name}_route"
      auth_value_method route_meth, default

      define_method(:"#{name}_path"){|opts=OPTS| route_path(send(route_meth), opts) if send(route_meth)}
      define_method(:"#{name}_url"){|opts=OPTS| route_url(send(route_meth), opts) if send(route_meth)}

      handle_meth = :"handle_#{name}"
      internal_handle_meth = :"_#{handle_meth}"
      before route_meth
      define_method(internal_handle_meth, &block)

      define_method(handle_meth) do
        request.is send(route_meth) do
          @current_route = name
          check_csrf if check_csrf?
          _around_rodauth do
            before_rodauth
            send(internal_handle_meth, request)
          end
        end
      end

      routes << handle_meth
    end

    def self.define(name, constant=nil, &block)
      feature = new
      feature.dependencies = []
      feature.routes = []
      feature.feature_name = name
      configuration = feature.configuration = FeatureConfiguration.new
      feature.module_eval(&block)
      configuration.def_configuration_methods(feature)

      # :nocov:
      if constant
      # :nocov:
        Rodauth.const_set(constant, feature)
        Rodauth::FeatureConfiguration.const_set(constant, configuration)
      end

      FEATURES[name] = feature
    end

    def internal_request_method(name=feature_name)
      (@internal_request_methods ||= []) << name
    end

    def uses_instance_variables(*ivs)
      @instance_variables_used = ivs.freeze
    end

    def configuration_module_eval(&block)
      configuration.module_eval(&block)
    end

    if RUBY_VERSION >= '2.5'
      DEPRECATED_ARGS = [{:uplevel=>1}]
    else
      # :nocov:
      DEPRECATED_ARGS = []
      # :nocov:
    end
    def def_deprecated_alias(new, old)
      configuration_module_eval do
        define_method(old) do |*a, &block|
          warn("Deprecated #{old} method used during configuration, switch to using #{new}", *DEPRECATED_ARGS)
          send(new, *a, &block)
        end
      end
      define_method(old) do
        warn("Deprecated #{old} method called at runtime, switch to using #{new}", *DEPRECATED_ARGS)
        send(new)
      end
    end

    DEFAULT_REDIRECT_BLOCK = proc{default_redirect}
    def redirect(name=feature_name, &block)
      meth = :"#{name}_redirect"
      block ||= DEFAULT_REDIRECT_BLOCK
      define_method(meth, &block)
      auth_value_methods meth
    end

    def view(page, title, name=feature_name)
      meth = :"#{name}_view"
      title_meth = :"#{name}_page_title"
      translatable_method(title_meth, title)
      define_method(meth) do
        view(page, send(title_meth))
      end
      auth_methods meth
    end

    def response(name=feature_name)
      meth = :"#{name}_response"
      overridable_meth = :"_#{meth}"
      notice_flash_meth = :"#{name}_notice_flash"
      redirect_meth = :"#{name}_redirect"
      define_method(overridable_meth) do
        set_notice_flash send(notice_flash_meth)
        redirect send(redirect_meth)
      end
      define_method(meth) do
        require_response(overridable_meth)
      end
      private overridable_meth, meth
      auth_private_methods meth
    end

    def loaded_templates(v)
      define_method(:loaded_templates) do
        super().concat(v)
      end
      private :loaded_templates
    end

    def depends(*deps)
      dependencies.concat(deps)
    end

    %w'after before'.each do |hook|
      define_method(hook) do |name=feature_name|
        meth = "#{hook}_#{name}"
        class_eval("def #{meth}; super if defined?(super); _#{meth}; hook_action(:#{hook}, :#{name}); nil end", __FILE__, __LINE__)
        class_eval("def _#{meth}; nil end", __FILE__, __LINE__)
        private meth, :"_#{meth}"
        auth_private_methods(meth)
      end
    end

    def email(type, subject, opts = OPTS)
      subject_method = :"#{type}_email_subject"
      body_method = :"#{type}_email_body"
      create_method = :"create_#{type}_email"
      send_method = :"send_#{type}_email"

      translatable_method subject_method, subject
      auth_methods create_method, send_method

      body_template = "#{type.to_s.tr('_', '-')}-email"
      if opts[:translatable]
        auth_value_methods body_method
        define_method(body_method){translate(body_method, render(body_template))}
      else
        auth_methods body_method
        define_method(body_method){render(body_template)}
      end

      define_method(create_method) do
        create_email(send(subject_method), send(body_method))
      end

      define_method(send_method) do
        send_email(send(create_method))
      end
    end

    def additional_form_tags(name=feature_name)
      auth_value_method(:"#{name}_additional_form_tags", nil)
    end

    def session_key(meth, value)
      define_method(meth){convert_session_key(value)}
      auth_value_methods(meth)
    end

    def flash_key(meth, value)
      define_method(meth){normalize_session_or_flash_key(value)}
      auth_value_methods(meth)
    end

    def auth_value_method(meth, value)
      define_method(meth){value}
      auth_value_methods(meth)
    end

    def translatable_method(meth, value)
      define_method(meth){translate(meth, value)}
      auth_value_methods(meth)
    end

    # Auth caching method that treats a nil instance variable as
    # not being cached. If nil is a valid value for the instance
    # variable, do not use this method, use a regular auth_method
    # and handle caching manually.
    def cached_auth_method(meth, iv=:"@#{meth}")
      umeth = :"_#{meth}"
      define_method(meth) do
        v = instance_variable_get(iv)
        v.nil? ? instance_variable_set(iv, send(umeth)) : v
      end
      alias_method(meth, meth)
      auth_private_methods(meth)
    end

    # :nocov:
    def auth_cached_method(meth, iv=:"@#{meth}") # :nodoc:
      # Non-shape friendly historical method.
      # RODAUTH3: Remove
      umeth = :"_#{meth}"
      define_method(meth) do
        if instance_variable_defined?(iv)
          instance_variable_get(iv)
        else
          instance_variable_set(iv, send(umeth))
        end
      end
      alias_method(meth, meth)
      auth_private_methods(meth)
    end
    # :nocov:

    [:notice_flash, :error_flash, :button].each do |meth|
      define_method(meth) do |v, name=feature_name|
        translatable_method(:"#{name}_#{meth}", v)
      end
    end
  end

  class Configuration
    attr_reader :auth

    def initialize(auth, &block)
      @auth = auth
      # :nocov:
      # Only for backwards compatibility
      # RODAUTH3: Remove
      apply(&block) if block
      # :nocov:
    end

    def apply(&block)
      load_feature(:base)
      instance_exec(&block)
    end

    def enable(*features)
      features.each do |feature|
        next if @auth.features.include?(feature)
        load_feature(feature)
        @auth.features << feature
      end
    end

    private

    def load_feature(feature_name)
      require "rodauth/features/#{feature_name}" unless FEATURES[feature_name]
      feature = FEATURES[feature_name]
      enable(*feature.dependencies)
      extend feature.configuration

      @auth.routes.concat(feature.routes)
      @auth.send(:include, feature)
    end
  end

  class Auth
    @features = []
    @routes = []
    @route_hash = {}
    @configuration = Configuration.new(self)

    class << self
      attr_accessor :roda_class
      attr_reader :features
      attr_reader :routes
      attr_accessor :route_hash
      attr_reader :configuration_name
      attr_reader :configuration

      private

      if RUBY_VERSION >= "3.2" && defined?(RubyVM::YJIT.enable)
        # Use a shape-friendly object on Ruby 3.2 if YJIT is available
        # with the assumption that it will be enabled later in any situation
        # desiring high performance.
        def make_shape_friendly
          ivs = instance_variables_used

          unless ivs.empty?
            ivs.uniq!
            ivs = ivs.reverse.join(" = ")
            method_content = "#{ivs} = nil"
            class_eval(<<-RUBY, __FILE__, __LINE__+1)
              private def _initialize_instance_variables
                #{method_content}
              end
              alias _initialize_instance_variables _initialize_instance_variables
            RUBY
          end

          nil
        end

        def instance_variables_used
          ivs = []
          features = []

          # Try to ensure that instance variable order follows feature enablement order
          ancestors.each do |mod|
            features << mod if mod.is_a?(Feature)
          end

          features.reverse_each do |mod|
            if (feature_ivs = mod.instance_variables_used)
              feature_ivs.each do |iv|
                unless iv.match?(/\A@[a-z_][a-z0-9_]*\z/)
                  raise ConfigurationError, "invalid model instance variable used"
                end

                ivs << iv
              end
            end
          end

          ivs
        end
      # :nocov:
      else
        def make_shape_friendly # :nodoc:
        end
      end
      # :nocov:
    end

    def self.inherited(subclass)
      super
      superclass = self
      subclass.instance_exec do
        @roda_class = superclass.roda_class
        @features = superclass.features.clone
        @routes = superclass.routes.clone
        @route_hash = superclass.route_hash.clone
        @configuration = superclass.configuration.clone
        @configuration.instance_variable_set(:@auth, self)
      end
    end

    def self.configure(&block)
      @configuration.apply(&block)
    end

    def self.freeze
      @features.freeze
      @routes.freeze
      @route_hash.freeze
      super
    end
  end

  module InstanceMethods
    def default_rodauth_name
      nil
    end

    def rodauth(name=default_rodauth_name)
      if name
        (@_rodauths ||= {})[name] ||= self.class.rodauth(name).new(self)
      else
        @_rodauth ||= self.class.rodauth.new(self)
      end
    end
  end

  module ClassMethods
    def rodauth(name=nil)
      opts[:rodauths][name]
    end

    def precompile_rodauth_templates
      instance = allocate
      rodauth = instance.rodauth

      view_opts = rodauth.send(:loaded_templates).map do |page|
        rodauth.send(:_view_opts, page)
      end
      view_opts << rodauth.send(:button_opts, '', OPTS)

      view_opts.each do |opts|
        instance.send(:retrieve_template, opts).send(:compiled_method, opts[:locals].keys.sort_by(&:to_s))
      end

      nil
    end

    def freeze
      opts[:rodauths].each_value(&:freeze)
      opts[:rodauths].freeze
      super
    end
  end

  module RequestMethods
    def rodauth(name=scope.default_rodauth_name)
      scope.rodauth(name).route!
    end
  end
end
