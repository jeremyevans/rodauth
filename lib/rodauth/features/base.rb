# frozen-string-literal: true

module Rodauth
  Feature.define(:base, :Base) do
    after 'login'
    after 'login_failure'
    before 'login'
    before 'login_attempt'
    before 'rodauth'
    after 'rodauth'

    error_flash "Please login to continue", 'require_login'

    auth_value_method :account_id_column, :id
    auth_value_method :account_open_status_value, 2
    auth_value_method :account_password_hash_column, nil
    auth_value_method :account_select, nil
    auth_value_method :account_status_column, :status_id
    auth_value_method :account_unverified_status_value, 1
    auth_value_method :accounts_table, :accounts
    auth_value_method :cache_templates, true
    auth_value_method :check_csrf_block, nil
    auth_value_method :check_csrf_opts, {}.freeze
    auth_value_method :default_redirect, '/'
    session_key :flash_error_key, :error
    session_key :flash_notice_key, :notice
    auth_value_method :hmac_secret, nil
    translatable_method :input_field_label_suffix, ''
    auth_value_method :input_field_error_class, 'error is-invalid'
    auth_value_method :input_field_error_message_class, 'error_message invalid-feedback'
    auth_value_method :invalid_field_error_status, 422
    auth_value_method :invalid_key_error_status, 401
    auth_value_method :invalid_password_error_status, 401
    translatable_method :invalid_password_message, "invalid password"
    auth_value_method :login_column, :email
    auth_value_method :login_required_error_status, 401
    auth_value_method :lockout_error_status, 403
    auth_value_method :password_hash_id_column, :id
    auth_value_method :password_hash_column, :password_hash
    auth_value_method :password_hash_table, :account_password_hashes
    auth_value_method :no_matching_login_error_status, 401
    translatable_method :no_matching_login_message, "no matching login"
    auth_value_method :login_param, 'login'
    translatable_method :login_label, 'Login'
    translatable_method :password_label, 'Password'
    auth_value_method :password_param, 'password'
    session_key :session_key, :account_id
    session_key :authenticated_by_session_key, :authenticated_by
    session_key :autologin_type_session_key, :autologin_type
    auth_value_method :prefix, ''
    auth_value_method :session_key_prefix, nil
    auth_value_method :require_bcrypt?, true
    auth_value_method :mark_input_fields_as_required?, true
    auth_value_method :mark_input_fields_with_autocomplete?, true
    auth_value_method :mark_input_fields_with_inputmode?, true
    auth_value_method :skip_status_checks?, true
    auth_value_method :template_opts, {}.freeze
    auth_value_method :title_instance_variable, nil 
    auth_value_method :token_separator, "_"
    auth_value_method :unmatched_field_error_status, 422
    auth_value_method :unopen_account_error_status, 403
    translatable_method :unverified_account_message, "unverified account, please verify account before logging in"
    auth_value_method :default_field_attributes, ''

    redirect(:require_login){"#{prefix}/login"}

    auth_value_methods(
      :base_url,
      :check_csrf?,
      :db,
      :domain,
      :login_input_type,
      :login_uses_email?,
      :modifications_require_password?,
      :set_deadline_values?,
      :use_date_arithmetic?,
      :use_database_authentication_functions?,
      :use_request_specific_csrf_tokens?
    )

    auth_methods(
      :account_id,
      :account_session_value,
      :already_logged_in,
      :authenticated?,
      :autocomplete_for_field?,
      :check_csrf,
      :clear_session,
      :csrf_tag,
      :function_name,
      :hook_action,
      :inputmode_for_field?,
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
      :translate,
      :unverified_account_message,
      :update_session
    )

    auth_private_methods(
      :account_from_login,
      :account_from_session,
      :field_attributes,
      :field_error_attributes,
      :formatted_field_error,
      :around_rodauth
    )

    configuration_module_eval do
      def auth_class_eval(&block)
        auth.class_eval(&block)
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

    def add_field_error_class(field)
      if field_error(field)
        " #{input_field_error_class}"
      end
    end

    def input_field_string(param, id, opts={})
      type = opts.fetch(:type, "text")

      unless type == "password"
        value = opts.fetch(:value){scope.h param(param)}
      end

      field_class = opts.fetch(:class, "form-control")

      if autocomplete_for_field?(param) && opts[:autocomplete]
        autocomplete = "autocomplete=\"#{opts[:autocomplete]}\""
      end

      if inputmode_for_field?(param) && opts[:inputmode]
        inputmode = "inputmode=\"#{opts[:inputmode]}\""
      end

      if mark_input_fields_as_required? && opts[:required] != false
        required = "required=\"required\""
      end

      "<input #{opts[:attr]} #{autocomplete} #{inputmode} #{required} #{field_attributes(param)} #{field_error_attributes(param)} type=\"#{type}\" class=\"#{field_class}#{add_field_error_class(param)}\" name=\"#{param}\" id=\"#{id}\" value=\"#{value}\"/> #{formatted_field_error(param) unless opts[:skip_error_message]}"
    end

    def autocomplete_for_field?(_param)
      mark_input_fields_with_autocomplete?
    end

    def inputmode_for_field?(_param)
      mark_input_fields_with_inputmode?
    end

    def field_attributes(field)
      _field_attributes(field) || default_field_attributes
    end

    def field_error_attributes(field)
      if field_error(field)
        _field_error_attributes(field)
      end
    end

    def formatted_field_error(field)
      if error = field_error(field)
        _formatted_field_error(field, error)
      end
    end

    def hook_action(_hook_type, _action)
      # nothing by default
    end

    def translate(_key, default)
      # do not attempt to translate by default
      default
    end

    # Return urlsafe base64 HMAC for data, assumes hmac_secret is set.
    def compute_hmac(data)
      s = [compute_raw_hmac(data)].pack('m').chomp!("=\n")
      s.tr!('+/', '-_')
      s
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

    def password_field_autocomplete_value
      @password_field_autocomplete_value || 'current-password'
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

    def login_input_type
      login_uses_email? ? 'email' : 'text'
    end

    def login_uses_email?
      login_column == :email
    end

    def clear_session
      if scope.respond_to?(:clear_session)
        scope.clear_session
      else
        session.clear
      end
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
      flash.now[flash_error_key] = message
    end

    def set_redirect_error_flash(message)
      flash[flash_error_key] = message
    end

    def set_notice_flash(message)
      flash[flash_notice_key] = message
    end

    def set_notice_now_flash(message)
      flash.now[flash_notice_key] = message
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

    def check_csrf
      scope.check_csrf!(check_csrf_opts, &check_csrf_block)
    end

    def csrf_tag(path=request.path)
      return unless scope.respond_to?(:csrf_tag)

      if use_request_specific_csrf_tokens?
        scope.csrf_tag(path)
      else
        # :nocov:
        scope.csrf_tag
        # :nocov:
      end
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
          password_hash_match?(hash, password)
        else
          database_function_password_match?(:rodauth_valid_password_hash, account_id, password, hash)
        end 
      end
    end

    def update_session
      clear_session
      set_session_value(session_key, account_session_value)
    end

    def authenticated_by
      session[authenticated_by_session_key]
    end

    def login_session(auth_type)
      update_session
      set_session_value(authenticated_by_session_key, [auth_type])
    end

    def autologin_type
      session[autologin_type_session_key]
    end

    def autologin_session(autologin_type)
      login_session('autologin')
      set_session_value(autologin_type_session_key, autologin_type)
    end

    # Return a string for the parameter name.  This will be an empty
    # string if the parameter doesn't exist.
    def param(key)
      param_or_nil(key).to_s
    end

    # Return a string for the parameter name, or nil if there is no
    # parameter with that name.
    def param_or_nil(key)
      value = raw_param(key)
      value.to_s unless value.nil?
    end

    def raw_param(key)
      request.params[key]
    end

    def base_url
      request.base_url
    end

    def domain
      request.host
    end

    def modifications_require_password?
      has_password?
    end

    def possible_authentication_methods
      has_password? ? ['password'] : []
    end

    private

    def _around_rodauth
      yield
    end

    def database_function_password_match?(name, hash_id, password, salt)
      db.get(Sequel.function(function_name(name), hash_id, BCrypt::Engine.hash_secret(password, salt)))
    end

    def password_hash_match?(hash, password)
      BCrypt::Password.new(hash) == password
    end

    def convert_token_key(key)
      if key && hmac_secret
        compute_hmac(key)
      else
        key
      end
    end

    def split_token(token)
      token.split(token_separator, 2)
    end

    def redirect(path)
      request.redirect(path)
    end

    def route_path(route, opts={})
      path  = "#{prefix}/#{route}"
      path += "?#{Rack::Utils.build_nested_query(opts)}" unless opts.empty?
      path
    end

    def route_url(route, opts={})
      "#{base_url}#{route_path(route, opts)}"
    end

    def transaction(opts={}, &block)
      db.transaction(opts, &block)
    end

    def random_key
      SecureRandom.urlsafe_base64(32)
    end

    def convert_session_key(key)
      key = "#{session_key_prefix}#{key}".to_sym if session_key_prefix
      scope.opts[:sessions_convert_symbols] ? key.to_s : key
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

    def use_request_specific_csrf_tokens?
      scope.opts[:rodauth_route_csrf] && scope.use_request_specific_csrf_tokens?
    end

    def check_csrf?
      scope.opts[:rodauth_route_csrf]
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

    def has_password?
      return @has_password if defined?(@has_password)
      return false unless account || session_value
      @has_password = !!get_password_hash
    end

    # Get the password hash for the user.  When using database authentication functions,
    # note that only the salt is returned.
    def get_password_hash
      if account_password_hash_column
        (account || account_from_session)[account_password_hash_column]
      elsif use_database_authentication_functions?
        db.get(Sequel.function(function_name(:rodauth_get_salt), account ? account_id : session_value))
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

    def compute_raw_hmac(data)
      OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, hmac_secret, data)
    end

    def _field_attributes(field)
      nil
    end

    def _field_error_attributes(field)
      " aria-invalid=\"true\" aria-describedby=\"#{field}_error_message\" "
    end

    def _formatted_field_error(field, error)
      "<span class=\"#{input_field_error_message_class}\" id=\"#{field}_error_message\">#{error}</span>"
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
      db[password_hash_table].where(password_hash_id_column=>account ? account_id : session_value)
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

    def remove_session_value(key)
      session.delete(key)
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
      opts = template_opts.dup
      opts[:locals] = opts[:locals] ? opts[:locals].dup : {}
      opts[:locals][:rodauth] = self
      opts[:cache] = cache_templates
      opts[:cache_key] = :"rodauth_#{page}"

      opts = scope.send(:find_template, scope.send(:parse_template_opts, page, opts))
      unless File.file?(scope.send(:template_path, opts))
        opts[:path] = template_path(page)
      end

      opts
    end

    def _view(meth, page)
      scope.send(meth, _view_opts(page))
    end
  end
end
