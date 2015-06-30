class Roda
  module RodaPlugins
    module Rodauth
      Base = Feature.define(:base) do
        auth_value_methods(
          :account_id,
          :account_model,
          :account_open_status_value,
          :account_password_hash_column,
          :account_status_id,
          :account_unverified_status_value,
          :default_redirect,
          :email_from,
          :login_column,
          :login_confirm_label,
          :login_confirm_param,
          :login_errors_message,
          :login_label,
          :login_param,
          :login_redirect,
          :logins_do_not_match_message,
          :no_matching_login_message,
          :password_confirm_label,
          :password_confirm_param,
          :password_does_not_meet_requirements_message,
          :password_hash_column,
          :password_hash_cost,
          :password_hash_table,
          :password_label,
          :password_minimum_length,
          :password_param,
          :passwords_do_not_match_message,
          :prefix,
          :require_login_notice_message,
          :require_login_redirect,
          :session_key,
          :skip_status_checks?,
          :title_instance_variable
        )

        auth_methods(
          :account_from_login,
          :account_from_session,
          :account_id_value,
          :clear_session,
          :email_to,
          :logged_in?,
          :open_account?,
          :password_hash,
          :password_meets_requirements?,
          :random_key,
          :require_login,
          :send_email,
          :session_value,
          :set_error_flash,
          :set_notice_flash,
          :set_password,
          :set_redirect_error_flash,
          :set_title,
          :unverified_account_message,
          :update_session
        )

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

        def flash
          scope.flash
        end

        # Overridable methods

        def session_value
          account.send(account_id)
        end
        alias account_id_value session_value

        def account_status_id_value
          account.send(account_status_id)
        end

        def _account_from_login(login)
          @account = account_from_login(login)
        end

        def account_from_login(login)
          ds = account_model.where(login_column=>login)
          ds = ds.where(account_status_id=>[account_unverified_status_value, account_open_status_value]) unless skip_status_checks?
          ds.first
        end

        def open_account?
          skip_status_checks? || account_status_id_value == account_open_status_value 
        end

        def unverified_account_message
          "unverified account, please verify account before logging in"
        end

        def update_session
          session[session_key] = session_value
        end

        def account_model
          ::Account
        end

        # If the account_password_hash_column is set, the password hash is verified in
        # ruby, it will not use a database function to do so, it will check the password
        # hash using bcrypt.
        def account_password_hash_column
          nil
        end

        def clear_session
          session.clear
        end

        def default_redirect
          '/'
        end

        def require_login_redirect
          "#{prefix}/login"
        end
        alias login_redirect require_login_redirect

        def require_login_notice_message
          "Please login to continue"
        end

        def prefix
          ''
        end

        def login_required
          set_notice_flash require_login_notice_message
          request.redirect require_login_redirect
        end

        def random_key
          require 'securerandom'
          SecureRandom.urlsafe_base64(32)
        end

        def title_instance_variable
          nil
        end

        def set_title(title)
          if title_instance_variable
            scope.instance_variable_set(title_instance_variable, title)
          end
        end

        def set_error_flash(message)
          flash.now[:error] = message
        end

        def set_redirect_error_flash(message)
          flash[:error] = message
        end

        def set_notice_flash(message)
          flash[:notice] = message
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

        def no_matching_login_message
          "no matching login"
        end

        def logged_in?
          session[session_key]
        end

        def login_param
          'login'
        end

        def login_confirm_param
          'login-confirm'
        end

        def login_label
          'Login'
        end

        def login_confirm_label
          "Confirm #{login_label}"
        end

        def password_label
          'Password'
        end

        def password_confirm_label
          "Confirm #{password_label}"
        end

        def login_errors_message
          if errors = account.errors.on(login_column)
            errors.join(', ')
          end
        end

        def logins_do_not_match_message
          'logins do not match'
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

        def passwords_do_not_match_message
          'passwords do not match'
        end

        def password_does_not_meet_requirements_message
          "invalid password, does not meet requirements (minimum #{password_minimum_length} characters)"
        end

        def password_minimum_length
          6
        end

        def password_meets_requirements?(password)
          password_minimum_length <= password.length
        end

        def account_unverified_status_value
          1
        end

        def account_open_status_value
          2
        end

        def _account_from_session
          @account = account_from_session
        end

        def account_from_session
          ds = account_model.where(account_id=>scope.session[session_key])
          ds = ds.where(account_status_id=>account_open_status_value) unless skip_status_checks?
          ds.first
        end

        def password_hash_cost
          require 'bcrypt'
          if ENV['RACK_ENV'] == 'test'
            BCrypt::Engine::MIN_COST
          else
            BCrypt::Engine::DEFAULT_COST
          end
        end

        def password_hash(password)
          require 'bcrypt'
          BCrypt::Password.create(password, :cost=>password_hash_cost)
        end

        def set_password(password)
          hash = password_hash(password)
          if account_password_hash_column
            account.set(:password_hash=>hash).save(:raise_on_save_failure=>true)
          else
            if account_model.db[password_hash_table].where(account_id=>account_id_value).update(password_hash_column=>hash) == 0
              account_model.db[password_hash_table].insert(account_id=>account_id_value, password_hash_column=>hash)
            end
          end
        end

        def transaction(&block)
          account_model.db.transaction(&block)
        end

        def email_from
          "webmaster@#{request.host}"
        end

        def email_to
          account.email
        end

        def send_email(subject, body)
          require 'mail'
          m = Mail.new
          m.from = email_from
          m.to = email_to
          m.subject = subject
          m.body = body
          m.deliver!
        end

        def view(page, title)
          set_title(title)
          _view(:view, page)
        end

        def render(page)
          _view(:render, page)
        end

        def skip_status_checks?
          false
        end

        def verify_created_accounts?
          false
        end

        def allow_reset_password?
          false
        end

        private

        def _view(meth, page)
          scope.instance_exec do
            template_opts = find_template(parse_template_opts(page, {}))
            unless File.file?(template_path(template_opts))
              template_opts[:path] = File.join(File.dirname(__FILE__), '../../../../templates', "#{page}.str")
            end
            send(meth, template_opts)
          end
        end
      end
    end
  end
end
