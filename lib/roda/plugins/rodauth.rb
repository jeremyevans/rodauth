require 'tilt/string'

class Roda
  module RodaPlugins
    module Rodauth
      def self.load_dependencies(app)
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

        def self.define(name, &block)
          feature = new
          feature.feature_name = name
          feature.module_eval(&block)
          FEATURES[name] = feature
        end

        DEFAULT_REDIRECT_BLOCK = proc{default_redirect}
        def redirect(&block)
          meth = :"#{feature_name}_redirect"
          block ||= DEFAULT_REDIRECT_BLOCK
          define_method(meth, &block)
          auth_value_methods meth
        end

        def view(page, title)
          meth = :"#{feature_name}_view"
          define_method(meth) do
            view(page, title)
          end
          auth_methods meth
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

        def require_login
          @login_required = true
        end

        def login_required?
          @login_required
        end

        [:route, :notice_flash, :error_flash].each do |meth|
          define_method(meth) do |v|
            inst_meth = :"#{feature_name}_#{meth}"
            define_method(inst_meth){v}
            auth_value_methods inst_meth
          end
        end

        [:get, :post, :route].each do |meth|
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
          attr_reader :route_block_methods
        end

        def self.inherited(subclass)
          super
          subclass.instance_exec do
            @features = []
            @route_block_methods = []
          end
        end

        def self.configure(&block)
          DSL.new(self, &block)
        end

        def self.freeze
          @features.freeze
          @route_block_methods.freeze
          super
        end

        def route_block_methods
          self.class.route_block_methods
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

        def def_auth_block_method(meth)
          define_sclass_method(meth) do |&block|
            _def_auth_method(meth){block}
          end
        end

        def initialize(auth, &block)
          @auth = auth
          load_feature(:base)
          instance_exec(&block)
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
          require "roda/plugins/rodauth/#{feature_name}"
          feature = FEATURES[feature_name]

          DSL_META_TYPES.each do |type|
            feature.send(:"#{type}_methods").each{|m| send(:"def_#{type}_method", m)}
          end

          if get_block = feature.get_block
            def_auth_block_method :"#{feature_name}_get_block"
            _def_auth_method(:"#{feature_name}_get_block"){get_block}
          end

          if post_block = feature.post_block
            def_auth_block_method :"#{feature_name}_post_block"
            _def_auth_method(:"#{feature_name}_post_block"){post_block}
          end

          route_block = feature.route_block
          if route_block || (get_block && post_block)
            before_meth = :"before_#{feature_name}"
            def_auth_block_method :"#{feature_name}_route_block"
            route_block ||= proc do |r, auth|
              r.is auth.send(:"#{feature_name}_route") do
                if feature.login_required? && !auth.logged_in?
                  auth.login_required
                end

                auth.send(before_meth)

                r.get do
                  instance_exec(r, auth, &auth.send(:"#{feature_name}_get_block"))
                end

                r.post do
                  instance_exec(r, auth, &auth.send(:"#{feature_name}_post_block"))
                end
              end
            end
            _def_auth_method(:"#{feature_name}_route_block"){route_block}
            _def_auth_method(before_meth){nil}
            def_auth_method(before_meth)
            @auth.route_block_methods << :"#{feature_name}_route_block"
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
          auth.route_block_methods.each do |meth|
            scope.instance_exec(self, auth, &auth.send(meth))
          end
        end
      end
    end

    register_plugin(:rodauth, Rodauth)
  end
end

