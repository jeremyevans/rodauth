require 'tilt/string'
require 'securerandom'

module Rodauth
  def self.load_dependencies(app, opts={})
    app.plugin :render
    app.plugin :flash
    app.plugin :h
  end

  def self.configure(app, opts={}, &block)
    ((app.opts[:rodauths] ||= {})[opts[:name]] ||= Class.new(Auth)).configure(&block)
  end

  DSL_META_TYPES = [:auth, :auth_value].freeze
  FEATURES = {}
  DSL_METHODS = {}

  class FeatureDSL < Module
    def initialize(feature)
      super()
      feature.auth_methods.each{|m| def_auth_method(m)}
      feature.auth_value_methods.each{|m| def_auth_value_method(m)}
    end

    private

    def def_auth_method(meth)
      define_method(meth) do |&block|
        @auth.send(:define_method, meth, &block)
      end
    end

    def def_auth_value_method(meth)
      define_method(meth) do |*v, &block|
        v = v.first
        block ||= proc{v}
        @auth.send(:define_method, meth, &block)
      end
    end
  end

  class Feature < Module
    DSL_META_TYPES.each do |meth|
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

    def self.define(name, &block)
      feature = new
      feature.dependencies = []
      feature.feature_name = name
      feature.module_eval(&block)

      if (get_block = feature.get_block) && (post_block = feature.post_block)
        before_meth = :"before_#{name}"
        feature.send(:define_method, before_meth){}
        feature.auth_methods before_meth
        feature.const_set(:ROUTE_BLOCK, proc do |r, auth|
          r.is auth.send(:"#{name}_route") do
            auth.check_before(feature)
            auth.send(before_meth)

            r.get do
              instance_exec(r, auth, &get_block)
            end

            r.post do
              instance_exec(r, auth, &post_block)
            end
          end
        end)
      end

      DSL_METHODS[name] = FeatureDSL.new(feature)
      FEATURES[name] = feature
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

    def after(name=feature_name)
      auth_value_method(:"after_#{name}", nil)
    end

    def additional_form_tags(name=feature_name)
      auth_value_method(:"#{name}_additional_form_tags", nil)
    end

    def auth_value_method(meth, value)
      define_method(meth){value}
      auth_value_methods(meth)
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
      attr_reader :route_blocks
    end

    def self.inherited(subclass)
      super
      subclass.instance_exec do
        @features = []
        @route_blocks = []
      end
    end

    def self.configure(&block)
      DSL.new(self, &block)
    end

    def self.freeze
      @features.freeze
      @route_blocks.freeze
      super
    end

    def route_blocks
      self.class.route_blocks
    end
  end

  class DSL
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
      extend DSL_METHODS[feature_name]

      if feature.const_defined?(:ROUTE_BLOCK)
        @auth.route_blocks << feature::ROUTE_BLOCK
      end

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
      auth = scope.rodauth(name)
      auth.route_blocks.each do |block|
        scope.instance_exec(self, auth, &block)
      end
    end
  end
end
