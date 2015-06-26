class Roda
  module RodaPlugins
    module Rodauth
      def self.load_dependencies(app)
        app.plugin :render
        app.plugin :h
      end

      def self.configure(app, &block)
        app.opts[:rodauth] ||= Class.new(Auth)
        app.opts[:rodauth].configure(&block)
      end

      class Error < RodaError; end

      DSL_META_TYPES = [:auth, :auth_block, :auth_value].freeze
      FEATURES = {}

      class Feature < Module
        DSL_META_TYPES.each do |meth|
          name = :"#{meth}_methods"
          define_method(name) do |*v|
            iv = :"@#{name}"
            v.empty? ? (instance_variable_get(iv) || []) : instance_variable_set(iv, v)
          end
        end

        def self.define(name)
          FEATURES[name] = new
        end
      end

      class Auth
        class << self
          attr_reader :features
        end

        def self.inherited(subclass)
          super
          subclass.instance_exec do
            @features = []
          end
        end

        def self.configure(&block)
          DSL.new(self, &block)
        end

        def self.freeze
          @features.freeze
          super
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
            _def_auth_method(:"#{meth}_block"){block}
          end
        end

        def initialize(auth, &block)
          @auth = auth
          load_feature(:base)
          instance_exec(&block)
        end

        def enable(*features)
          features.each{|f| load_feature(f)}
          @auth.features.concat(features.map{|m| :"#{m}_route_block"}).uniq
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
          @auth.include(feature)
        end
      end

      module InstanceMethods
        def rodauth
          @_rodauth ||= self.class.rodauth.new(self)
        end
      end

      module ClassMethods
        def rodauth
          opts[:rodauth]
        end

        def freeze
          rodauth.freeze
          super
        end
      end

      module RequestMethods
        def rodauth
          auth = scope.rodauth
          auth.features.each do |meth|
            scope.instance_exec(self, &auth.send(meth))
          end
        end
      end
    end

    register_plugin(:rodauth, Rodauth)
  end
end

