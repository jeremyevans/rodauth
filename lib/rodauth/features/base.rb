module Rodauth
  Base = Feature.define(:base) do
    auth_value_method :account_id, :id
    auth_value_method :account_open_status_value, 2
    auth_value_method :account_password_hash_column, nil
    auth_value_method :account_status_id, :status_id
    auth_value_method :account_unverified_status_value, 1
    auth_value_method :default_redirect, '/'
    auth_value_method :email_subject_prefix, nil
    auth_value_method :invalid_password_message, "invalid password"
    auth_value_method :login_column, :email
    auth_value_method :password_hash_column, :password_hash
    auth_value_method :password_hash_table, :account_password_hashes
    auth_value_method :no_matching_login_message, "no matching login"
    auth_value_method :login_param, 'login'
    auth_value_method :login_confirm_param, 'login-confirm'
    auth_value_method :login_label, 'Login'
    auth_value_method :password_label, 'Password'
    auth_value_method :logins_do_not_match_message, 'logins do not match'
    auth_value_method :password_param, 'password'
    auth_value_method :password_confirm_param, 'password-confirm'
    auth_value_method :session_key, :account_id
    auth_value_method :passwords_do_not_match_message, 'passwords do not match'
    auth_value_method :password_minimum_length, 6
    auth_value_method :require_login_notice_message, "Please login to continue"
    auth_value_method :prefix, ''
    auth_value_method :require_bcrypt?, true
    auth_value_method :require_mail?, false 
    auth_value_method :title_instance_variable, nil 

    auth_value_methods(
      :account_model,
      :email_from,
      :login_confirm_label,
      :password_confirm_label,
      :password_does_not_meet_requirements_message,
      :password_hash_cost,
      :require_login_redirect,
      :skip_status_checks?,
      :set_deadline_values?,
      :use_date_arithmetic?,
      :use_database_authentication_functions?
    )

    auth_methods(
      :account_from_login,
      :account_from_session,
      :account_id_value,
      :account_session_value,
      :after_close_account,
      :already_logged_in,
      :clear_session,
      :create_email,
      :email_to,
      :logged_in?,
      :login_errors_message,
      :login_required,
      :open_account?,
      :password_hash,
      :password_match?,
      :password_meets_requirements?,
      :random_key,
      :session_value,
      :set_error_flash,
      :set_notice_flash,
      :set_notice_now_flash,
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

    def account_id_value
      account.send(account_id)
    end
    alias account_session_value account_id_value

    def session_value
      session[session_key]
    end

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
      clear_session
      session[session_key] = account_session_value
    end

    def check_before(feature)
      meth = :"check_before_#{feature.feature_name}"
      if respond_to?(meth)
        send(meth)
      elsif feature.account_required?
        require_account
      elsif logged_in?
        already_logged_in 
      end
    end

    def account_model
      ::Account
    end

    def db
      account_model.db
    end

    # If the account_password_hash_column is set, the password hash is verified in
    # ruby, it will not use a database function to do so, it will check the password
    # hash using bcrypt.
    def account_password_hash_column
      nil
    end

    def already_logged_in
      nil
    end

    def clear_session
      session.clear
    end

    def require_login_redirect
      "#{prefix}/login"
    end

    def login_required
      set_notice_flash require_login_notice_message
      request.redirect require_login_redirect
    end

    def random_key
      if RUBY_VERSION >= '1.9'
        SecureRandom.urlsafe_base64(32)
      else
        # :nocov:
        SecureRandom.hex(32)
        # :nocov:
      end
    end

    def timing_safe_eql?(provided, actual)
      provided = provided.to_s
      provided.ljust(actual.length)
      match = true
      actual.length.times do |i|
        match = false unless provided[i] == actual[i]
      end
      match = false unless provided.length == actual.length
      match
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

    def set_notice_now_flash(message)
      flash.now[:notice] = message
    end

    def logged_in?
      session[session_key]
    end

    def require_login
      login_required unless logged_in?
    end

    def require_account
      require_login
      unless _account_from_session
        clear_session
        login_required
      end
    end

    def login_confirm_label
      "Confirm #{login_label}"
    end

    def password_confirm_label
      "Confirm #{password_label}"
    end

    def login_errors_message
      if errors = account.errors.on(login_column)
        errors.join(', ')
      end
    end

    def password_does_not_meet_requirements_message
      "invalid password, does not meet requirements (minimum #{password_minimum_length} characters)"
    end

    def password_meets_requirements?(password)
      password_minimum_length <= password.length
    end

    def account_initial_status_value
      account_open_status_value
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
      if ENV['RACK_ENV'] == 'test'
        BCrypt::Engine::MIN_COST
      else
        # :nocov:
        BCrypt::Engine::DEFAULT_COST
        # :nocov:
      end
    end

    def password_hash(password)
      BCrypt::Password.create(password, :cost=>password_hash_cost)
    end

    def set_password(password)
      hash = password_hash(password)
      if account_password_hash_column
        account.set(account_password_hash_column=>hash).save_changes(:raise_on_save_failure=>true)
      else
        if db[password_hash_table].where(account_id=>account_id_value).update(password_hash_column=>hash) == 0
          db[password_hash_table].insert(account_id=>account_id_value, password_hash_column=>hash)
        end
      end
    end

    def transaction(&block)
      db.transaction(&block)
    end

    def email_from
      "webmaster@#{request.host}"
    end

    def email_to
      account.email
    end

    def create_email(subject, body)
      m = Mail.new
      m.from = email_from
      m.to = email_to
      m.subject = "#{email_subject_prefix}#{subject}"
      m.body = body
      m
    end

    def view(page, title)
      set_title(title)
      _view(:view, page)
    end

    def render(page)
      _view(:render, page)
    end

    def skip_status_checks?
      !account_model.columns.include?(account_status_id)
    end

    def after_close_account
    end

    def post_configure
      require 'bcrypt' if require_bcrypt?
      require 'mail' if require_mail?
      db.extension :date_arithmetic if use_date_arithmetic?
    end

    def use_date_arithmetic?
      set_deadline_values?
    end

    def set_deadline_values?
      db.database_type == :mysql
    end

    def use_database_authentication_functions?
      db.database_type == :postgres || db.database_type == :mysql
    end

    def password_match?(password)
      if account_password_hash_column
        BCrypt::Password.new(account.send(account_password_hash_column)) == password
      elsif use_database_authentication_functions?
        id = account.send(account_id)
        if salt = db.get{rodauth_get_salt(id)}
          hash = BCrypt::Engine.hash_secret(password, salt)
          db.get{rodauth_valid_password_hash(id, hash)}
        end
      else
        hash = db[password_hash_table].
          where(account_id=>account.send(account_id)).
          get(password_hash_column)
        if hash
          BCrypt::Password.new(hash) == password
        end
      end
    end

    private

    def set_deadline_value(hash, column, interval)
      if set_deadline_values?
        hash[column] = Sequel.date_add(Sequel::CURRENT_TIMESTAMP, interval)
      end
    end

    def _view(meth, page)
      auth = self
      scope.instance_exec do
        template_opts = find_template(parse_template_opts(page, :locals=>{:rodauth=>auth}))
        unless File.file?(template_path(template_opts))
          template_opts[:path] = File.join(File.dirname(__FILE__), '../../../templates', "#{page}.str")
        end
        send(meth, template_opts)
      end
    end
  end
end
