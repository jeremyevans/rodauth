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

      SUPPORTED_FEATURES = [:login, :logout, :change_password, :reset_password, :verify_account, :create_account, :close_account].freeze

      class Auth
        class DSL
          def self.def_auth_method(meth)
            define_method(meth) do |&block|
              def_auth_method(meth, &block)
            end
          end

          def self.def_auth_value_method(meth)
            define_method(meth) do |*v, &block|
              v = v.first
              block ||= proc{v}
              def_auth_method(meth, &block)
            end
          end

          def self.def_auth_block_method(meth)
            define_method(meth) do |&block|
              def_auth_method(:"#{meth}_block"){block}
            end
          end

          def initialize(auth, &block)
            @auth = auth
            instance_exec(&block)
          end

          def def_auth_method(meth, &block)
            @auth.send(:define_method, meth, &block)
          end

          def enable(*features)
            unsupported_features = features - SUPPORTED_FEATURES
            raise Error, "unsupported Rodauth module(s) enabled: #{unsupported_features.join(", ")}" unless unsupported_features.empty?

            @auth.features.concat(features.map{|m| :"rodauth_#{m}"}).uniq
          end

          def account_model(model)
            def_auth_method(:model){model}
          end

          [
            :login,
            :logout,
          ].each do |meth|
            def_auth_block_method meth
          end

          [
            :model,
            :login_column,
            :session_key,
            :account_id,
            :login_param,
            :password_param,
            :prefix,
            :no_matching_login_message,
            :invalid_password_message,
            :login_route,
            :logout_route,
            :login_redirect,
            :logout_redirect,
          ].each do |meth|
            def_auth_value_method meth
          end

          [
            :account_from_login,
            :update_session,
            :password_match?,
            :session_value,
            :set_title,
          ].each do |meth|
            def_auth_method meth
          end
        end

        class Wrapper
          def initialize(auth, obj)
            @auth = auth
            @obj = obj
          end

          def self.def_delegate_method(meth)
            define_method(meth) do |*args|
              @auth.send(meth, @obj, *args)
            end
          end

          [:password_match?, :update_session].each do |meth|
            def_delegate_method(meth)
          end
        end

        # Internals

        module ClassMethods
          attr_reader :features

          def inherited(subclass)
            super
            subclass.instance_exec do
              @features = []
            end
          end

          def configure(&block)
            DSL.new(self, &block)
          end

          def freeze
            @features.freeze
            super
          end
        end
        extend ClassMethods

        module InstanceMethods
          attr_reader :scope

          def initialize(scope)
            @scope = scope
          end

          def features
            self.class.features
          end

          def request
            scope.request
          end

          def wrap(obj)
            if obj
              Wrapper.new(self, obj)
            end
          end

          # Overridable methods

          def login_block
            proc do |r|
              auth = rodauth
              auth.clear_session(session)

              if account = auth.wrap(auth.account_from_login(r[auth.login_param].to_s))
                if account.password_match?(r[auth.password_param].to_s)
                  account.update_session(session)
                  r.redirect auth.login_redirect
                else
                  if auth.features.include?(:rodauth_reset_password)
                    @password_reset_login = r[auth.login_param].to_s
                  end
                  @password_error = auth.invalid_password_message
                end
              else
                @login_error = auth.no_matching_login_message
              end

              rodauth_view('login', 'Login')
            end
          end

          def logout_block
            proc do |r|
              auth = rodauth
              auth.clear_session(session)
              r.redirect auth.logout_redirect
            end
          end

          def clear_session(session)
            session.clear
          end

          def model
            ::Account
          end

          def login_route
            'login'
          end

          def logout_route
            'logout'
          end

          def login_redirect
            '/'
          end

          def logout_redirect
            "#{prefix}/login"
          end

          def login_column
            :email
          end

          def login_param
            'login'
          end

          def password_param
            'password'
          end

          def session_key
            :account_id
          end

          def no_matching_login_message
            "no matching login"
          end

          def invalid_password_message
            "invalid password"
          end

          def session_value(obj)
            obj.send(account_id)
          end

          def account_id
            :id
          end

          def prefix
            ''
          end

          def set_title(title)
          end

          def account_from_login(login)
            model.where(login_column=>login).first
          end

          def update_session(obj, session)
            session[session_key] = session_value(obj)
          end

          def password_match?(obj, password)
            model.db.get{|db| db.account_valid_password(obj.send(account_id), password)}
          end
        end
        include InstanceMethods
      end

      module InstanceMethods
        def rodauth
          @_rodauth ||= self.class.rodauth.new(self)
        end

        def rodauth_view(page, title)
          rodauth.set_title(title)
          template_opts = find_template(parse_template_opts(page, {}))
          unless File.file?(template_path(template_opts))
            template_opts[:path] = File.join(File.dirname(__FILE__), '../../../templates', "#{page}.str")
          end
          view(template_opts)
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
            send(meth, auth)
          end
        end

        private

        def rodauth_login(auth)
          is auth.login_route do
            get do
              scope.rodauth_view('login', 'Login')
            end

            post do
              scope.instance_exec(self, &auth.login_block)
            end
          end
        end

        def rodauth_logout(auth)
          is auth.logout_route do
            get do
              scope.rodauth_view('logout', 'Logout')
            end

            post do
              scope.instance_exec(self, &auth.logout_block)
            end
          end
        end
      end
    end

    register_plugin(:rodauth, Rodauth)
  end
end

