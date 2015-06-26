class Roda
  module RodaPlugins
    module Rodauth
      Base = Feature.define(:base)
      Base.module_eval do
        auth_value_methods :account_model, :prefix, :session_key, :account_id, :account_status_id, :account_open_status_value,
          :login_column, :login_param, :password_param, :password_confirm_param, :password_hash_column, :password_hash_table,
          :password_hash_cost
        auth_methods :set_title, :clear_session, :account_from_session, :password_hash

        attr_reader :scope
        attr_reader :account

        def initialize(scope)
          @scope = scope
        end

        def features
          self.class.features
        end

        def request
          scope.request
        end

        def response
          scope.response
        end

        def session
          scope.session
        end

        # Overridable methods

        def account_model
          ::Account
        end

        def clear_session
          session.clear
        end

        def prefix
          ''
        end

        def set_title(title)
        end

        def login_column
          :email
        end

        def password_hash_column
          :password_hash
        end

        def password_hash_table
          :account_password_hashes
        end

        def login_param
          'login'
        end

        def password_param
          'password'
        end

        def password_confirm_param
          'password-confirm'
        end

        def session_key
          :account_id
        end

        def account_id
          :id
        end

        def account_status_id
          :status_id
        end

        def account_open_status_value
          2
        end

        def account_from_session
          @account = account_model.where(account_status_id=>account_open_status_value, account_id=>scope.session[session_key]).first
        end

        def password_hash_cost
          BCrypt::Engine::DEFAULT_COST
        end

        def password_hash(password)
          BCrypt::Password.create(password, :cost=>password_hash_cost)
        end

        def set_password(password)
          hash = password_hash(password)
          if account_model.db[password_hash_table].where(account_id=>account.send(account_id)).update(password_hash_column=>hash) == 0
            account_model.db[password_hash_table].insert(account_id=>account.send(account_id), password_hash_column=>hash)
          end
        end

        def transaction(&block)
          account_model.db.transaction(&block)
        end

        def view(page, title)
          set_title(title)
          scope.instance_exec do
            template_opts = find_template(parse_template_opts(page, {}))
            unless File.file?(template_path(template_opts))
              template_opts[:path] = File.join(File.dirname(__FILE__), '../../../../templates', "#{page}.str")
            end
            view(template_opts)
          end
        end

        def verify_created_accounts?
          false
        end

        def allow_password_reset?
          false
        end
      end
    end
  end
end
