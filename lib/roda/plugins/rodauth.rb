class Roda
  module RodaPlugins
    module Rodauth
      def self.load_dependencies(app)
        app.plugin :render
        app.plugin :h
      end

      def self.configure(app, &block)
        app.opts[:rodauth] ||= Auth.new
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
            define_method(meth) do |v|
              def_auth_method(meth){v}
            end
          end

          def self.def_auth_block_method(meth)
            define_method(meth) do |&block|
              def_auth_method(:"#{meth}_block"){block}
            end
          end

          def initialize(auth, &block)
            @auth = auth
            @auth_class = class << auth; self; end
            instance_exec(&block)
          end

          def def_auth_method(meth, &block)
            @auth_class.send(:define_method, meth, &block)
          end

          def enable(*features)
            unsupported_features = features - SUPPORTED_FEATURES
            raise Error, "unsupported Rodauth module(s) enabled: #{unsupported_features.join(", ")}" unless unsupported_features.empty?

            @auth.features.concat(features.map{|m| :"rodauth_#{m}"}).uniq
          end

          def set_title(&block)
            @auth.title_block = block
          end

          def account_model(model)
            def_auth_method(:model){model}
          end

          [
            :login,
          ].each do |meth|
            def_auth_block_method meth
          end

          [
            :model,
            :login_column,
            :session_key,
            :account_id,
            :login_param,
            :login_redirect,
            :password_param,
            :prefix,
            :no_matching_login_message,
            :invalid_password_message,
          ].each do |meth|
            def_auth_value_method meth
          end

          [
            :account_from_login,
            :update_session,
            :password_match?,
            :session_value,
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

        attr_reader :features
        attr_accessor :title_block

        def initialize
          @features = []
        end

        def configure(&block)
          DSL.new(self, &block)
        end

        def freeze
          @features.freeze
          super
        end

        def wrap(obj)
          if obj
            Wrapper.new(self, obj)
          end
        end

        # Overridable methods

        def login_block
          proc do |r|
            auth = self.class.rodauth

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

        def model
          ::Account
        end

        def login_redirect
          '/'
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

      module InstanceMethods
        def rodauth_view(page, title)
          template_opts = find_template(parse_template_opts(page, {}))
          unless File.file?(template_path(template_opts))
            if title_block = self.class.rodauth.title_block
              instance_exec(title, &title_block)
            end
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
          roda_class.rodauth.features.each do |meth|
            send(meth)
          end
        end

        private

        def rodauth_login
          is 'login' do
            get do
              scope.rodauth_view('login', 'Login')
            end

            post do
              scope.instance_exec(self, &roda_class.rodauth.login_block)
            end
          end
        end
      end
    end

    register_plugin(:rodauth, Rodauth)
  end
end

