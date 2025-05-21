# frozen-string-literal: true

require 'rack/request'
require 'rack/utils'

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
    auth_value_method :check_csrf_block, nil
    auth_value_method :check_csrf_opts, {}.freeze
    auth_value_method :default_redirect, '/'
    auth_value_method :convert_token_id_to_integer?, nil
    flash_key :flash_error_key, :error
    flash_key :flash_notice_key, :notice
    auth_value_method :hmac_old_secret, nil
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
    auth_value_method :max_param_bytesize, 1024
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
    translatable_method :strftime_format, '%F %T'
    auth_value_method :template_opts, {}.freeze
    auth_value_method :title_instance_variable, nil 
    auth_value_method :token_separator, "_"
    auth_value_method :unmatched_field_error_status, 422
    auth_value_method :unopen_account_error_status, 403
    translatable_method :unverified_account_message, "unverified account, please verify account before logging in"
    auth_value_method :default_field_attributes, ''
    auth_value_method :use_template_fixed_locals?, true

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
      :normalize_login,
      :null_byte_parameter_value,
      :open_account?,
      :over_max_bytesize_param_value,
      :password_match?,
      :random_key,
      :redirect,
      :session_value,
      :set_error_flash,
      :set_notice_flash,
      :set_notice_now_flash,
      :set_redirect_error_flash,
      :set_error_reason,
      :set_title,
      :translate,
      :update_session
    )

    auth_private_methods(
      :account_from_id,
      :account_from_login,
      :account_from_session,
      :convert_token_id,
      :field_attributes,
      :field_error_attributes,
      :formatted_field_error,
      :around_rodauth
    )

    internal_request_method :account_exists?
    internal_request_method :account_id_for_login
    internal_request_method :internal_request_eval

    configuration_module_eval do
      def auth_class_eval(&block)
        auth.class_eval(&block)
      end
    end

    attr_reader :scope
    attr_reader :account
    attr_reader :current_route

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
      _process_raw_hmac(compute_raw_hmac(data))
    end

    # Return urlsafe base64 HMAC for data using hmac_old_secret, assumes hmac_old_secret is set.
    def compute_old_hmac(data)
      _process_raw_hmac(compute_raw_hmac_with_secret(data, hmac_old_secret))
    end

    # Return array of hmacs.  Array has two strings if hmac_old_secret
    # is set, or one string otherwise.
    def compute_hmacs(data)
      hmacs = [compute_hmac(data)]

      if hmac_old_secret
        hmacs << compute_old_hmac(data)
      end

      hmacs
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
      Sequel::DATABASES.first or raise "Sequel database connection is missing"
    end

    def login_field_autocomplete_value
      login_uses_email? ? "email" : "on"
    end

    def password_field_autocomplete_value
      @password_field_autocomplete_value || 'current-password'
    end

    alias account_password_hash_column account_password_hash_column
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
      if use_scope_clear_session?
        scope.clear_session
      else
        session.clear
      end
    end

    def login_required
      set_redirect_error_status(login_required_error_status)
      set_error_reason :login_required
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

    def require_account
      require_authentication
      require_account_session
    end

    def account_initial_status_value
      account_open_status_value
    end

    def account!
      account || (session_value && account_from_session)
    end

    def account_from_session
      @account = _account_from_session
    end

    def account_from_id(id, status_id=nil)
      @account = _account_from_id(id, status_id)
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
      _merge_fixed_locals_opts(opts, button_fixed_locals)
      opts[:locals] = {:value=>value, :opts=>opts}
      opts[:cache] = cache_templates
      opts[:cache_key] = :rodauth_button
      _template_opts(opts, 'button')
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

      if method(:convert_token_id_to_integer?).owner == Rodauth::Base && (db rescue false) && db.table_exists?(accounts_table) && db.schema(accounts_table).find{|col, v| break v[:type] == :integer if col == account_id_column}
        self.class.send(:define_method, :convert_token_id_to_integer?){true}
      end

      route_hash= {}
      self.class.routes.each do |meth|
        route_meth = "#{meth.to_s.sub(/\Ahandle_/, '')}_route"
        if route = send(route_meth)
          route_hash["/#{route}"] = meth
        end
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
      unless value.nil?
        value = value.to_s
        value = over_max_bytesize_param_value(key, value) if max_param_bytesize && value.bytesize > max_param_bytesize
        value = null_byte_parameter_value(key, value) if value && value.include?("\0")
      end
      value
    end

    # Return nil by default for values over maximum bytesize.
    def over_max_bytesize_param_value(key, value)
      nil
    end

    # The normalized value of the login parameter
    def login_param_value
      normalize_login(param(login_param))
    end

    def normalize_login(login)
      login
    end

    # Return nil by default for values with null bytes
    def null_byte_parameter_value(key, value)
      nil
    end

    def raw_param(key)
      request.params[key]
    end

    def base_url
      url = String.new("#{request.scheme}://#{domain}")
      url << ":#{request.port}" if request.port != Rack::Request::DEFAULT_PORTS[request.scheme]
      url
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

    def has_password?
      return @has_password if defined?(@has_password)
      return false unless account || session_value
      @has_password = !!get_password_hash
    end

    private

    def _around_rodauth
      yield
    end

    def _process_raw_hmac(hmac)
      s = [hmac].pack('m')
      s.chomp!("=\n")
      s.tr!('+/', '-_')
      s
    end

    if Rack.release >= '3'
      def set_response_header(key, value)
        response.headers[key] = value
      end

      def convert_response_header_key(key)
        key
      end
    # :nocov:
    else
      def set_response_header(key, value)
        response.headers[convert_response_header_key(key)] = value
      end

      # Attempt backwards compatibility on Rack < 3 by changing
      # known cases from lower case to mixed case.
      mixed_case_headers = {}
      (<<-END).split.each { |k| mixed_case_headers[k.downcase.freeze] = k.freeze }
        Access-Control-Allow-Headers
        Access-Control-Allow-Methods
        Access-Control-Allow-Origin
        Access-Control-Expose-Headers
        Access-Control-Max-Age
        Allow
        Authorization
        Content-Type
        Content-Length
        WWW-Authenticate
      END
      mixed_case_headers.freeze
      define_method(:convert_response_header_key) do |key|
        mixed_case_headers.fetch(key, key)
      end
    end
    # :nocov:

    if RUBY_VERSION >= '2.1'
      def button_fixed_locals
        '(value:, opts:)'
      end
    # :nocov:
    else
      # Work on Ruby 2.0 when using Tilt 2.6+, as Ruby 2.0 does
      # not support required keyword arguments.
      def button_fixed_locals
        '(value: nil, opts: nil)'
      end
    end
    # :nocov:

    def database_function_password_match?(name, hash_id, password, salt)
      db.get(Sequel.function(function_name(name), hash_id, password_hash_using_salt(password, salt)))
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

    def convert_token_id(id)
      if convert_token_id_to_integer?
        convert_token_id_to_integer(id)
      else
        id
      end
    end

    def convert_token_id_to_integer(id)
      if id = (Integer(id, 10) rescue nil)
        if id > 9223372036854775807 || id < -9223372036854775808
          # Only allow 64-bit signed integer range to avoid problems on PostgreSQL
          id = nil
        end
      end

      id
    end

    def redirect(path)
      request.redirect(path)
    end

    def return_response(body=nil)
      response.write(body) if body
      request.halt
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
      key = :"#{session_key_prefix}#{key}" if session_key_prefix
      normalize_session_or_flash_key(key)
    end

    def normalize_session_or_flash_key(key)
      scope.opts[:sessions_convert_symbols] ? key.to_s : key
    end

    def timing_safe_eql?(provided, actual)
      provided = provided.to_s
      Rack::Utils.secure_compare(provided.ljust(actual.length), actual) && provided.length == actual.length
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
    
    def set_response_error_reason_status(reason, status)
      set_error_reason(reason)
      set_response_error_status(status)
    end

    def throw_rodauth_error
      throw :rodauth_error
    end

    def throw_error(field, error)
      set_field_error(field, error)
      throw_rodauth_error
    end

    def throw_error_status(status, field, error)
      set_response_error_status(status)
      throw_error(field, error)
    end

    def set_error_reason(reason)
    end

    def throw_error_reason(reason, status, field, message)
      set_error_reason(reason)
      throw_error_status(status, field, message)
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

    def password_hash_using_salt(password, salt)
      BCrypt::Engine.hash_secret(password, salt)
    end

    # Get the password hash for the user.  When using database authentication functions,
    # note that only the salt is returned.
    def get_password_hash
      if account_password_hash_column
        account[account_password_hash_column] if account!
      elsif use_database_authentication_functions?
        db.get(Sequel.function(function_name(:rodauth_get_salt), account ? account_id : session_value))
      else
        # :nocov:
        password_hash_ds.get(password_hash_column)
        # :nocov:
      end
    end

    def _account_from_login(login)
      ds = account_table_ds.where(login_column=>login)
      ds = ds.select(*account_select) if account_select
      ds = ds.where(account_status_column=>[account_unverified_status_value, account_open_status_value]) unless skip_status_checks?
      ds.first
    end

    def _account_from_session
      ds = account_ds(session_value)
      ds = ds.where(account_session_status_filter) unless skip_status_checks?
      ds.first
    end

    def _account_from_id(id, status_id=nil)
      ds = account_ds(id)
      ds = ds.where(account_status_column=>status_id) if status_id && !skip_status_checks?
      ds.first
    end

    def hmac_secret_rotation?
      hmac_secret && hmac_old_secret && hmac_secret != hmac_old_secret
    end

    def compute_raw_hmac(data)
      raise ConfigurationError, "hmac_secret not set" unless hmac_secret
      compute_raw_hmac_with_secret(data, hmac_secret)
    end

    def compute_raw_hmac_with_secret(data, secret)
      OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, secret, data)
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
      ds = account_table_ds.where(account_id_column=>id)
      ds = ds.select(*account_select) if account_select
      ds
    end

    def account_table_ds
      db[accounts_table]
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

    def _filter_links(links)
      links.select!{|_, link| link}
      links.sort!
      links
    end

    def internal_request?
      false
    end

    def use_scope_clear_session?
      scope.respond_to?(:clear_session)
    end

    def require_response(meth)
      send(meth)
      raise ConfigurationError, "#{meth.to_s.sub(/\A_/, '')} overridden without returning a response (should use redirect or request.halt)."
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
          hash[k] = Sequel::CURRENT_TIMESTAMP == v ? Time.now : v
        end
      end
      num
    end

    def update_account(values, ds=account_ds)
      update_hash_ds(account, ds, values)
    end

    def _view_opts(page)
      opts = template_opts.dup
      _merge_fixed_locals_opts(opts, '(rodauth: self.rodauth)')
      opts[:locals] = opts[:locals] ? opts[:locals].dup : {}
      opts[:locals][:rodauth] = self
      opts[:cache] = cache_templates
      opts[:cache_key] = :"rodauth_#{page}"
      _template_opts(opts, page)
    end

    def _merge_fixed_locals_opts(opts, fixed_locals)
      if use_template_fixed_locals? && !opts[:locals]
        fixed_locals_opts = {default_fixed_locals: fixed_locals}
        fixed_locals_opts.merge!(opts[:template_opts]) if opts[:template_opts]
        opts[:template_opts] = fixed_locals_opts
      end
    end

    # Set the template path only if there isn't an overridden template in the application.
    # Result should replace existing template opts.
    def _template_opts(opts, page)
      opts = scope.send(:find_template, scope.send(:parse_template_opts, page, opts))
      unless File.file?(scope.send(:template_path, opts))
        opts[:path] = template_path(page)
      end
      opts
    end

    def _view(meth, page)
      unless scope.respond_to?(meth)
        raise ConfigurationError, "attempted to render a built-in view/email template (#{page.inspect}), but rendering is disabled"
      end

      scope.send(meth, _view_opts(page))
    end
  end
end
