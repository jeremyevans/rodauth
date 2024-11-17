# frozen-string-literal: true

require 'stringio'

module Rodauth
  INVALID_DOMAIN = "invalidurl @@.com"

  class InternalRequestError < StandardError
    attr_accessor :flash
    attr_accessor :reason
    attr_accessor :field_errors

    def initialize(attrs)
      return super if attrs.is_a?(String)

      @flash = attrs[:flash]
      @reason = attrs[:reason]
      @field_errors = attrs[:field_errors] || {}

      super(build_message)
    end

    private

    def build_message
      extras = []
      extras << reason if reason
      extras << field_errors unless field_errors.empty?
      extras = (" (#{extras.join(", ")})" unless extras.empty?)

      "#{flash}#{extras}"
    end
  end

  module InternalRequestMethods
    attr_accessor :session
    attr_accessor :params
    attr_reader :flash
    attr_accessor :internal_request_block

    def domain
      d = super
      if d.nil? || d == INVALID_DOMAIN
        raise InternalRequestError, "must set domain in configuration, as it cannot be determined from internal request"
      end
      d
    end

    def raw_param(k)
      @params[k]
    end

    def clear_session
      @session.clear
    end

    def set_error_flash(message)
      @flash = message
      _handle_internal_request_error
    end
    alias set_redirect_error_flash set_error_flash

    def set_notice_flash(message)
      @flash = message
    end
    alias set_notice_now_flash set_notice_flash

    def modifications_require_password?
      false
    end
    alias require_login_confirmation? modifications_require_password?
    alias require_password_confirmation? modifications_require_password?
    alias change_login_requires_password? modifications_require_password?
    alias change_password_requires_password? modifications_require_password?
    alias close_account_requires_password? modifications_require_password?
    alias two_factor_modifications_require_password? modifications_require_password?

    def otp_setup_view
      hash = {:otp_setup=>otp_user_key}
      hash[:otp_setup_raw] = otp_key if hmac_secret
      _return_from_internal_request(hash)
    end

    def add_recovery_codes_view
      _return_from_internal_request(recovery_codes)
    end

    def webauthn_setup_view
      cred = new_webauthn_credential
      _return_from_internal_request({
        webauthn_setup: cred.as_json,
        webauthn_setup_challenge: cred.challenge,
        webauthn_setup_challenge_hmac: compute_hmac(cred.challenge)
      })
    end

    def webauthn_auth_view
      cred = webauthn_credential_options_for_get
      _return_from_internal_request({
        webauthn_auth: cred.as_json,
        webauthn_auth_challenge: cred.challenge,
        webauthn_auth_challenge_hmac: compute_hmac(cred.challenge)
      })
    end

    def handle_internal_request(meth)
      catch(:halt) do
        _around_rodauth do
          before_rodauth
          send(meth, request)
        end
      end

      @internal_request_return_value
    end

    def only_json?
      false
    end

    private

    def internal_request?
      true
    end

    def set_error_reason(reason)
      @error_reason = reason
    end

    def after_login
      super
      _set_internal_request_return_value(account_id) unless @return_false_on_error
    end

    def after_remember
      super
      if params[remember_param] == remember_remember_param_value
        _set_internal_request_return_value("#{account_id}_#{convert_token_key(remember_key_value)}")
      end
    end

    def after_load_memory
      super
      _return_from_internal_request(session_value)
    end

    def before_change_password_route
      super
      params[new_password_param] ||= params[password_param]
    end

    def before_email_auth_request_route
      super
      _set_login_param_from_account
    end

    def before_login_route
      super
      _set_login_param_from_account
    end

    def before_unlock_account_request_route
      super
      _set_login_param_from_account
    end

    def before_reset_password_request_route
      super
      _set_login_param_from_account
    end

    def before_verify_account_resend_route
      super
      _set_login_param_from_account
    end

    def before_webauthn_login_route
      super
      _set_login_param_from_account
    end

    def account_from_key(token, status_id=nil)
      return super unless session_value
      return unless yield session_value
      _account_from_id(session_value, status_id)
    end

    def _set_internal_request_return_value(value)
      @internal_request_return_value = value
    end

    def _return_from_internal_request(value)
      _set_internal_request_return_value(value)
      throw(:halt)
    end

    def _handle_internal_request_error
      if @return_false_on_error
        _return_from_internal_request(false)
      else
        raise InternalRequestError.new(flash: @flash, reason: @error_reason, field_errors: @field_errors)
      end
    end

    def _return_false_on_error!
      @return_false_on_error = true
    end

    def _set_login_param_from_account
      if session_value && !params[login_param] && (account = _account_from_id(session_value))
        params[login_param] = account[login_column]
      end
    end

    def _get_remember_cookie
      params[remember_param]
    end

    def _handle_internal_request_eval(_)
      v = instance_eval(&internal_request_block)
      _set_internal_request_return_value(v) unless defined?(@internal_request_return_value)
    end

    def _handle_account_id_for_login(_)
      raise InternalRequestError, "no login provided" unless param_or_nil(login_param)
      raise InternalRequestError, "no account for login" unless account = account_from_login(login_param_value)
      _return_from_internal_request(account[account_id_column])
    end

    def _handle_account_exists?(_)
      raise InternalRequestError, "no login provided" unless param_or_nil(login_param)
      _return_from_internal_request(!!account_from_login(login_param_value))
    end

    def _handle_lock_account(_)
      raised_uniqueness_violation{account_lockouts_ds(session_value).insert(_setup_account_lockouts_hash(session_value, generate_unlock_account_key))}
    end

    def _handle_remember_setup(request)
      params[remember_param] = remember_remember_param_value
      _handle_remember(request)
    end

    def _handle_remember_disable(request)
      params[remember_param] = remember_disable_param_value
      _handle_remember(request)
    end

    def _handle_account_id_for_remember_key(request)
      load_memory
      raise InternalRequestError, "invalid remember key"
    end

    def _handle_otp_setup_params(request)
      request.env['REQUEST_METHOD'] = 'GET'
      _handle_otp_setup(request)
    end

    def _handle_webauthn_setup_params(request)
      request.env['REQUEST_METHOD'] = 'GET'
      _handle_webauthn_setup(request)
    end

    def _handle_webauthn_auth_params(request)
      request.env['REQUEST_METHOD'] = 'GET'
      _handle_webauthn_auth(request)
    end

    def _handle_webauthn_login_params(request)
      _set_login_param_from_account
      unless webauthn_login_options?
        raise InternalRequestError, "no login provided" unless param_or_nil(login_param)
        raise InternalRequestError, "no account for login"
      end
      webauthn_auth_view
    end

    def _predicate_internal_request(meth, request)
      _return_false_on_error!
      _set_internal_request_return_value(true)
      send(meth, request)
    end

    def _handle_valid_login_and_password?(request)
      _predicate_internal_request(:_handle_login, request)
    end

    def _handle_valid_email_auth?(request)
      _predicate_internal_request(:_handle_email_auth, request)
    end

    def _handle_valid_otp_auth?(request)
      _predicate_internal_request(:_handle_otp_auth, request)
    end

    def _handle_valid_recovery_auth?(request)
      _predicate_internal_request(:_handle_recovery_auth, request)
    end

    def _handle_valid_sms_auth?(request)
      _predicate_internal_request(:_handle_sms_auth, request)
    end
  end

  module InternalRequestClassMethods
    def internal_request(route, opts={}, &block)
      opts = opts.dup
      
      env = {
         'REQUEST_METHOD'=>'POST',
         'PATH_INFO'=>'/'.dup,
         "SCRIPT_NAME" => "",
         "HTTP_HOST" => INVALID_DOMAIN,
         "SERVER_NAME" => INVALID_DOMAIN,
         "SERVER_PORT" => 443,
         "CONTENT_TYPE" => "application/x-www-form-urlencoded",
         "rack.input"=>StringIO.new(''),
         "rack.url_scheme"=>"https"
      }
      env.merge!(opts.delete(:env)) if opts[:env]

      session = {}
      session.merge!(opts.delete(:session)) if opts[:session]

      params = {}
      params.merge!(opts.delete(:params)) if opts[:params]

      scope = roda_class.new(env)
      rodauth = new(scope)
      rodauth.session = session
      rodauth.params = params
      rodauth.internal_request_block = block

      unless account_id = opts.delete(:account_id)
        if (account_login = opts.delete(:account_login))
          if (account = rodauth.send(:_account_from_login, account_login))
            account_id = account[rodauth.account_id_column]
          else
            raise InternalRequestError, "no account for login: #{account_login.inspect}"
          end
        end
      end

      if account_id
        session[rodauth.session_key] = account_id
        unless authenticated_by = opts.delete(:authenticated_by)
          authenticated_by = case route
          when :otp_auth, :sms_request, :sms_auth, :recovery_auth, :webauthn_auth, :webauthn_auth_params, :valid_otp_auth?, :valid_sms_auth?, :valid_recovery_auth?
            ['internal1']
          else
            ['internal1', 'internal2']
          end
        end
        session[rodauth.authenticated_by_session_key] = authenticated_by
      end

      opts.keys.each do |k|
        meth = :"#{k}_param"
        params[rodauth.public_send(meth).to_s] = opts.delete(k) if rodauth.respond_to?(meth)
      end

      unless opts.empty?
        warn "unhandled options passed to #{route}: #{opts.inspect}"
      end

      rodauth.handle_internal_request(:"_handle_#{route}")
    end
  end

  Feature.define(:internal_request, :InternalRequest) do
    configuration_module_eval do
      def internal_request_configuration(&block)
        @auth.instance_exec do
          (@internal_request_configuration_blocks ||= []) << block
        end
      end
    end

    def post_configure
      super

      return if is_a?(InternalRequestMethods)

      superklasses = []
      superklass = self.class
      until superklass == Rodauth::Auth
        superklasses << superklass
        superklass = superklass.superclass
      end

      klass = self.class
      internal_class = Class.new(klass)
      internal_class.instance_variable_set(:@configuration_name, klass.configuration_name)
      configuration = internal_class.configuration

      superklasses.reverse_each do |superklass|
        if blocks = superklass.instance_variable_get(:@internal_request_configuration_blocks)
          blocks.each do |block|
            configuration.instance_exec(&block)
          end
        end
      end

      internal_class.send(:extend, InternalRequestClassMethods)
      internal_class.send(:include, InternalRequestMethods)
      internal_class.allocate.post_configure

      ([:base] + internal_class.features).each do |feature_name|
        feature = FEATURES[feature_name]
        if meths = feature.internal_request_methods
          meths.each do |name|
            klass.define_singleton_method(name){|opts={}, &block| internal_class.internal_request(name, opts, &block)}
          end
        end
      end

      klass.const_set(:InternalRequest, internal_class)
      klass.private_constant :InternalRequest
    end
  end
end
