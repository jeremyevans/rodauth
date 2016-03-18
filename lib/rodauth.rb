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

      FEATURES[name] = feature
    end

    DEFAULT_REDIRECT_BLOCK = proc{default_redirect}
    def redirect(&block)
      meth = :"#{feature_name}_redirect"
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

    def after
      meth = :"after_#{feature_name}"
      define_method(meth) do
        nil
      end
      auth_methods meth
    end

    def additional_form_tags
      meth = :"#{feature_name}_additional_form_tags"
      define_method(meth) do
        nil
      end
      auth_value_methods meth
    end

    def require_account
      @account_required = true
    end

    def account_required?
      @account_required
    end

    [:route, :notice_flash, :error_flash, :button].each do |meth|
      define_method(meth) do |v|
        inst_meth = :"#{feature_name}_#{meth}"
        define_method(inst_meth){v}
        auth_value_methods inst_meth
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
    def def_auth_method(meth)
      define_sclass_method(meth) do |&block|
        _def_auth_method(meth, &block)
      end
    end

    def def_auth_value_method(meth)
      define_sclass_method(meth) do |*v, &block|
        v = v.first
        block ||= proc{v}
        _def_auth_method(meth, &block)
      end
    end

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

    def _def_auth_method(meth, &block)
      @auth.send(:define_method, meth, &block)
    end

    def define_sclass_method(meth, &block)
      (class << self; self end).send(:define_method, meth, &block)
    end

    def load_feature(feature_name)
      require "rodauth/features/#{feature_name}"
      feature = FEATURES[feature_name]
      enable(*feature.dependencies)

      DSL_META_TYPES.each do |type|
        feature.send(:"#{type}_methods").each{|m| send(:"def_#{type}_method", m)}
      end

      if feature.const_defined?(:ROUTE_BLOCK)
        before_meth = :"before_#{feature.name}"
        _def_auth_method(before_meth){nil}
        def_auth_method(before_meth)
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
