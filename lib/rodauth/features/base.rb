# frozen-string-literal: true

module Rodauth
  Feature.define(:base, :Base) do
    after 'login'
    after 'login_failure'
    before 'login'
    before 'login_attempt'
    before 'rodauth'

    error_flash "Please login to continue", 'require_login'

    auth_value_method :account_id_column, :id
    auth_value_method :account_open_status_value, 2
    auth_value_method :account_password_hash_column, nil
    auth_value_method :account_select, nil
    auth_value_method :account_status_column, :status_id
    auth_value_method :account_unverified_status_value, 1
    auth_value_method :accounts_table, :accounts
    auth_value_method :cache_templates, true
    auth_value_method :default_redirect, '/'
    auth_value_method :invalid_field_error_status, 422
    auth_value_method :invalid_key_error_status, 401
    auth_value_method :invalid_password_error_status, 401
    auth_value_method :invalid_password_message, "invalid password"
    auth_value_method :login_column, :email
    auth_value_method :login_required_error_status, 401
    auth_value_method :lockout_error_status, 403
    auth_value_method :password_hash_id_column, :id
    auth_value_method :password_hash_column, :password_hash
    auth_value_method :password_hash_table, :account_password_hashes
    auth_value_method :no_matching_login_error_status, 401
    auth_value_method :no_matching_login_message, "no matching login"
    auth_value_method :login_param, 'login'
    auth_value_method :login_label, 'Login'
    auth_value_method :password_label, 'Password'
    auth_value_method :password_param, 'password'
    auth_value_method :modifications_require_password?, true
    auth_value_method :session_key, :account_id
    auth_value_method :prefix, ''
    auth_value_method :require_bcrypt?, true
    auth_value_method :skip_status_checks?, true
    auth_value_method :template_opts, {}
    auth_value_method :title_instance_variable, nil 
    auth_value_method :unmatched_field_error_status, 422
    auth_value_method :unopen_account_error_status, 403
    auth_value_method :unverified_account_message, "unverified account, please verify account before logging in"

    redirect(:require_login){"#{prefix}/login"}

    auth_value_methods(
      :db,
      :require_login_redirect,
      :set_deadline_values?,
      :use_date_arithmetic?,
      :use_database_authentication_functions?
    )

    auth_methods(
      :account_id,
      :account_session_value,
      :already_logged_in,
      :authenticated?,
      :clear_session,
      :csrf_tag,
      :function_name,
      :logged_in?,
      :login_required,
      :open_account?,
      :password_match?,
      :random_key,
      :redirect,
      :session_value,
      :set_error_flash,
      :set_notice_flash,
      :set_notice_now_flash,
      :set_redirect_error_flash,
      :set_title,
      :unverified_account_message,
      :update_session
    )

    auth_private_methods(
      :account_from_login,
      :account_from_session
    )

    configuration_module_eval do
      def auth_class_eval(&block)
        auth.class_eval(&block)
      end

      def account_model(model)
        warn "account_model is deprecated, use db and accounts_table settings"
        db model.db
        accounts_table model.table_name
        account_select model.dataset.opts[:select]
      end
    end

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

    def route!
      if meth = self.class.route_hash[request.remaining_path]
        send(meth)
      end

      nil
    end

    def set_field_error(field, error)
      (@field_errors ||= {})[field] = error
    end

    def field_error(field)
      return nil unless @field_errors
      @field_errors[field]
    end

    def account_id
      account[account_id_column]
    end
    alias account_session_value account_id

    def session_value
      session[session_key]
    end
    alias logged_in? session_value

    def account_from_login(login)
      @account = _account_from_login(login)
    end

    def open_account?
      skip_status_checks? || account[account_status_column] == account_open_status_value 
    end

    def db
      Sequel::DATABASES.first
    end

    # If the account_password_hash_column is set, the password hash is verified in
    # ruby, it will not use a database function to do so, it will check the password
    # hash using bcrypt.
    def account_password_hash_column
      nil
    end

    def check_already_logged_in
      already_logged_in if logged_in?
    end

    def already_logged_in
      nil
    end

    def clear_session
      session.clear
    end

    def login_required
      set_redirect_error_status(login_required_error_status)
      set_redirect_error_flash require_login_error_flash
      redirect require_login_redirect
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

    def require_login
      login_required unless logged_in?
    end

    def authenticated?
      logged_in?
    end

    def require_authentication
      require_login
    end

    def account_initial_status_value
      account_open_status_value
    end

    def account_from_session
      @account = _account_from_session
    end

    def csrf_tag
      scope.csrf_tag if scope.respond_to?(:csrf_tag)
    end

    def button_opts(value, opts)
      opts = Hash[template_opts].merge!(opts)
      opts[:locals] = {:value=>value, :opts=>opts}
      opts[:path] = template_path('button')
      opts[:cache] = cache_templates
      opts[:cache_key] = :rodauth_button
      opts
    end

    def button(value, opts={})
      scope.render(button_opts(value, opts))
    end

    def view(page, title)
      set_title(title)
      _view(:view, page)
    end

    def render(page)
      _view(:render, page)
    end

    def only_json?
      scope.class.opts[:rodauth_json] == :only
    end

    def post_configure
      require 'bcrypt' if require_bcrypt?
      db.extension :date_arithmetic if use_date_arithmetic?
      route_hash= {}
      self.class.routes.each do |meth|
        route_hash["/#{send("#{meth.to_s.sub(/\Ahandle_/, '')}_route")}"] = meth
      end
      self.class.route_hash = route_hash.freeze
    end

    def password_match?(password)
      if hash = get_password_hash
        if account_password_hash_column || !use_database_authentication_functions?
          BCrypt::Password.new(hash) == password
        else
          db.get(Sequel.function(function_name(:rodauth_valid_password_hash), account_id, BCrypt::Engine.hash_secret(password, hash)))
        end 
      end
    end

    def update_session
      clear_session
      session[session_key] = account_session_value
    end

    # Return a string for the parameter name.  This will be an empty
    # string if the parameter doesn't exist.
    def param(key)
      param_or_nil(key).to_s
    end

    # Return a string for the parameter name, or nil if there is no
    # parameter with that name.
    def param_or_nil(key)
      value = request.params[key]
      value.to_s unless value.nil?
    end

    private

    def redirect(path)
      request.redirect(path)
    end

    def transaction(opts={}, &block)
      db.transaction(opts, &block)
    end

    if RUBY_VERSION >= '1.9'
      def random_key
        SecureRandom.urlsafe_base64(32)
      end
    else
      # :nocov:
      def random_key
        SecureRandom.hex(32)
      end
      # :nocov:
    end

    def timing_safe_eql?(provided, actual)
      provided = provided.to_s
      Rack::Utils.secure_compare(provided.ljust(actual.length), actual) && provided.length == actual.length
    end

    def require_account
      require_authentication
      require_account_session
    end

    def require_account_session
      unless account_from_session
        clear_session
        login_required
      end
    end

    def catch_error(&block)
      catch(:rodauth_error, &block)
    end

    # Don't set an error status when redirecting in an error case, as a redirect status is needed.
    def set_redirect_error_status(status)
    end

    def set_response_error_status(status)
      response.status = status
    end

    def throw_error(field, error)
      set_field_error(field, error)
      throw :rodauth_error
    end

    def throw_error_status(status, field, error)
      set_response_error_status(status)
      throw_error(field, error)
    end

    def use_date_arithmetic?
      set_deadline_values?
    end

    def set_deadline_values?
      db.database_type == :mysql
    end

    def use_database_authentication_functions?
      case db.database_type
      when :postgres, :mysql, :mssql
        true
      else
        # :nocov:
        false
        # :nocov:
      end
    end

    def function_name(name)
      if db.database_type == :mssql
        # :nocov:
        "dbo.#{name}"
        # :nocov:
      else
        name
      end
    end

    # Get the password hash for the user.  When using database authentication functions,
    # note that only the salt is returned.
    def get_password_hash
      if account_password_hash_column
        account[account_password_hash_column]
      elsif use_database_authentication_functions?
        db.get(Sequel.function(function_name(:rodauth_get_salt), account_id))
      else
        # :nocov:
        password_hash_ds.get(password_hash_column)
        # :nocov:
      end
    end

    def _account_from_login(login)
      ds = db[accounts_table].where(login_column=>login)
      ds = ds.select(*account_select) if account_select
      ds = ds.where(account_status_column=>[account_unverified_status_value, account_open_status_value]) unless skip_status_checks?
      ds.first
    end

    def _account_from_session
      ds = account_ds(session_value)
      ds = ds.where(account_session_status_filter) unless skip_status_checks?
      ds.first
    end

    def account_session_status_filter
      {account_status_column=>account_open_status_value}
    end

    def template_path(page)
      File.join(File.dirname(__FILE__), '../../../templates', "#{page}.str")
    end

    def account_ds(id=account_id)
      raise ArgumentError, "invalid account id passed to account_ds" unless id
      ds = db[accounts_table].where(account_id_column=>id)
      ds = ds.select(*account_select) if account_select
      ds
    end

    def password_hash_ds
      db[password_hash_table].where(password_hash_id_column=>account_id)
    end

    # This is needed for jdbc/sqlite, which returns timestamp columns as strings
    def convert_timestamp(timestamp)
      timestamp = db.to_application_timestamp(timestamp) if timestamp.is_a?(String)
      timestamp
    end

    def loaded_templates
      []
    end

    # This is used to avoid race conditions when using the pattern of inserting when
    # an update affects no rows.  In such cases, if a row is inserted between the
    # update and the insert, the insert will fail with a uniqueness error, but
    # retrying will work.  It is possible for it to fail again, but only if the row
    # is deleted before the update and readded before the insert, which is very
    # unlikely to happen.  In such cases, raising an exception is acceptable.
    def retry_on_uniqueness_violation(&block)
      if raises_uniqueness_violation?(&block)
        yield
      end
    end

    # In cases where retrying on uniqueness violations cannot work, this will detect
    # whether a uniqueness violation is raised by the block and return the exception if so.
    # This method should be used if you don't care about the exception itself.
    def raises_uniqueness_violation?(&block)
      transaction(:savepoint=>:only, &block)
      false
    rescue unique_constraint_violation_class => e
      e
    end

    # Work around jdbc/sqlite issue where it only raises ConstraintViolation and not
    # UniqueConstraintViolation.
    def unique_constraint_violation_class
      if db.adapter_scheme == :jdbc && db.database_type == :sqlite
        # :nocov:
        Sequel::ConstraintViolation
        # :nocov:
      else
        Sequel::UniqueConstraintViolation
      end
    end

    # If you would like to operate/reraise the exception, this alias makes more sense.
    alias raised_uniqueness_violation raises_uniqueness_violation?

    # If you just want to ignore uniqueness violations, this alias makes more sense.
    alias ignore_uniqueness_violation raises_uniqueness_violation?

    # This is needed on MySQL, which doesn't support non constant defaults other than
    # CURRENT_TIMESTAMP.
    def set_deadline_value(hash, column, interval)
      if set_deadline_values?
        # :nocov:
        hash[column] = Sequel.date_add(Sequel::CURRENT_TIMESTAMP, interval)
        # :nocov:
      end
    end

    def set_session_value(key, value)
      session[key] = value
    end

    def update_hash_ds(hash, ds, values)
      num = ds.update(values)
      if num == 1
        values.each do |k, v|
          account[k] = v == Sequel::CURRENT_TIMESTAMP ? Time.now : v
        end
      end
      num
    end

    def update_account(values, ds=account_ds)
      update_hash_ds(account, ds, values)
    end

    def _view_opts(page)
      auth_template_path = template_path(page)
      opts = template_opts.dup
      opts[:locals] = opts[:locals] ? opts[:locals].dup : {}
      opts[:locals][:rodauth] = self
      opts[:cache] = cache_templates
      opts[:cache_key] = :"rodauth_#{page}"

      scope.instance_exec do
        opts = find_template(parse_template_opts(page, opts))
        unless File.file?(template_path(opts))
          opts[:path] = auth_template_path
        end
      end

      opts
    end

    def _view(meth, page)
      scope.send(meth, _view_opts(page))
    end
  end
end
