require 'tilt/string'
require 'securerandom'

module Rodauth
  def self.load_dependencies(app, opts={})
    if opts[:json]
      app.plugin :json
      app.plugin :json_parser
    end

    unless opts[:json] == :only
      app.plugin :render
      app.plugin :csrf
      app.plugin :flash
      app.plugin :h
    end
  end

  def self.configure(app, opts={}, &block)
    ((app.opts[:rodauths] ||= {})[opts[:name]] ||= Class.new(Auth)).configure(&block)
  end

  FEATURES = {}

  class FeatureConfiguration < Module
    def def_configuration_methods(feature)
      private_methods = feature.private_instance_methods.map(&:to_sym)
      priv = proc{|m| private_methods.include?(m)}
      feature.auth_methods.each{|m| def_auth_method(m, priv[m])}
      feature.auth_value_methods.each{|m| def_auth_value_method(m, priv[m])}
      feature.auth_private_methods.each{|m| def_auth_private_method(m)}
    end

    private

    def def_auth_method(meth, priv)
      define_method(meth) do |&block|
        @auth.send(:define_method, meth, &block)
        @auth.send(:private, meth) if priv
      end
    end

    def def_auth_private_method(meth)
      umeth = :"_#{meth}"
      define_method(meth) do |&block|
        @auth.send(:define_method, umeth, &block)
        @auth.send(:private, umeth)
      end
    end

    def def_auth_value_method(meth, priv)
      define_method(meth) do |*v, &block|
        v = v.first
        block ||= proc{v}
        @auth.send(:define_method, meth, &block)
        @auth.send(:private, meth) if priv
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

    def handle(name=feature_name, &block)
      meth = "handle_#{name}"
      define_method(meth, &block)
      routes << meth
    end

    def handle_route(route=feature_name.to_s, name=feature_name, opts={}, &block)
      route(route, name) if route

      route_meth = :"#{name}_route"
      before route_meth
      before_meth = :"before_#{route_meth}"
      feature = self
      check_before_meth = opts[:check_before]
      no_before = opts[:no_before]

      handle(name) do
        request.is send(route_meth) do
          before_rodauth
          send(check_before_meth) if check_before_meth
          send(before_meth) unless no_before
          instance_exec(&block)
        end
      end
    end

    def handle_get_post
      return unless get_block = @get_block
      return unless post_block = @post_block

      handle_route(nil, feature_name, :check_before=>(account_required? ? :require_account : :check_already_logged_in)) do
        request.get do
          instance_exec(&get_block)
        end

        request.post do
          instance_exec(&post_block)
        end
      end
    end

    def self.define(name, &block)
      feature = new
      feature.dependencies = []
      feature.routes = []
      feature.feature_name = name
      configuration = feature.configuration = FeatureConfiguration.new
      feature.module_eval(&block)
      feature.handle_get_post
      configuration.def_configuration_methods(feature)
      FEATURES[name] = feature
    end

    def configuration_module_eval(&block)
      configuration.module_eval(&block)
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
      define_method(meth) do
        view(page, title)
      end
      auth_methods meth
    end

    def depends(*deps)
      dependencies.concat(deps)
    end

    %w'after before'.each do |hook|
      define_method(hook) do |*args|
        name = args[0] || feature_name
        meth = "#{hook}_#{name}"
        class_eval("def #{meth}; super if defined?(super); _#{meth} end", __FILE__, __LINE__)
        class_eval("def _#{meth}; nil end", __FILE__, __LINE__)
        private :"_#{meth}"
        auth_private_methods(meth)
      end
    end

    def additional_form_tags(name=feature_name)
      auth_value_method(:"#{name}_additional_form_tags", nil)
    end

    def auth_value_method(meth, value)
      define_method(meth){value}
      auth_value_methods(meth)
    end

    def auth_cached_method(meth, iv=:"@#{meth}")
      umeth = :"_#{meth}"
      define_method(meth) do
        if instance_variable_defined?(iv)
          instance_variable_get(iv)
        else
          instance_variable_set(iv, send(umeth))
        end
      end
      auth_private_methods(meth)
    end

    def require_account
      @account_required = true
    end

    def account_required?
      @account_required
    end

    [:route, :notice_flash, :error_flash, :button].each do |meth|
      define_method(meth) do |v, *args|
        name = args.shift || feature_name
        auth_value_method(:"#{name}_#{meth}", v)
      end
    end

    [:get, :post].each do |meth|
      define_method("#{meth}_block") do |&block|
        if block
          instance_variable_set("@#{meth}_block", block)
        else
          instance_variable_get("@#{meth}_block")
        end
      end
    end
  end

  class Auth
    class << self
      attr_reader :features
      attr_reader :routes
    end

    def self.inherited(subclass)
      super
      subclass.instance_exec do
        @features = []
        @routes = []
      end
    end

    def self.configure(&block)
      Configuration.new(self, &block)
    end

    def self.freeze
      @features.freeze
      @routes.freeze
      super
    end

    def routes
      self.class.routes
    end
  end

  class Configuration
    attr_reader :auth

    def initialize(auth, &block)
      @auth = auth
      load_feature(:base)
      instance_exec(&block)
      auth.allocate.post_configure
    end

    def enable(*features)
      new_features = features - @auth.features
      new_features.each{|f| load_feature(f)}
      @auth.features.concat(new_features)
    end

    private

    def load_feature(feature_name)
      require "rodauth/features/#{feature_name}"
      feature = FEATURES[feature_name]
      enable(*feature.dependencies)
      extend feature.configuration

      @auth.routes.concat(feature.routes)
      @auth.send(:include, feature)
    end
  end

  module InstanceMethods
    def rodauth(name=nil)
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

    def freeze
      if opts[:rodauths]
        opts[:rodauths].each_value(&:freeze)
        opts[:rodauths].freeze
      end
      super
    end
  end

  module RequestMethods
    def rodauth(name=nil)
      scope.rodauth(name).route!
    end
  end
end
