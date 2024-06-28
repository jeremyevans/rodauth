# frozen-string-literal: true

require 'rotp'
require 'rqrcode'

module Rodauth
  Feature.define(:otp, :Otp) do
    depends :two_factor_base

    additional_form_tags 'otp_disable'
    additional_form_tags 'otp_auth'
    additional_form_tags 'otp_setup'

    after 'otp_authentication_failure'
    after 'otp_disable'
    after 'otp_setup'

    before 'otp_authentication'
    before 'otp_setup'
    before 'otp_disable'

    button 'Authenticate Using TOTP', 'otp_auth'
    button 'Disable TOTP Authentication', 'otp_disable'
    button 'Setup TOTP Authentication', 'otp_setup'

    error_flash "Error disabling TOTP authentication", 'otp_disable'
    error_flash "Error logging in via TOTP authentication", 'otp_auth'
    error_flash "Error setting up TOTP authentication", 'otp_setup'
    error_flash "You have already setup TOTP authentication", 'otp_already_setup'
    error_flash "TOTP authentication code use locked out due to numerous failures", 'otp_lockout'

    notice_flash "TOTP authentication has been disabled", 'otp_disable'
    notice_flash "TOTP authentication is now setup", 'otp_setup'

    redirect :otp_disable
    redirect :otp_already_setup
    redirect :otp_setup
    response :otp_disable
    response :otp_setup
    redirect(:otp_lockout){two_factor_auth_required_redirect}

    loaded_templates %w'otp-disable otp-auth otp-setup otp-auth-code-field password-field'
    view 'otp-disable', 'Disable TOTP Authentication', 'otp_disable'
    view 'otp-auth', 'Enter Authentication Code', 'otp_auth'
    view 'otp-setup', 'Setup TOTP Authentication', 'otp_setup'

    translatable_method :otp_auth_link_text, "Authenticate Using TOTP"
    translatable_method :otp_setup_link_text, "Setup TOTP Authentication"
    translatable_method :otp_disable_link_text, "Disable TOTP Authentication"

    auth_value_method :otp_auth_failures_limit, 5
    translatable_method :otp_auth_label, 'Authentication Code'
    auth_value_method :otp_auth_param, 'otp'
    auth_value_method :otp_class, ROTP::TOTP
    auth_value_method :otp_digits, nil
    auth_value_method :otp_drift, 30
    auth_value_method :otp_interval, nil
    translatable_method :otp_invalid_auth_code_message, "Invalid authentication code"
    translatable_method :otp_invalid_secret_message, "invalid secret"
    auth_value_method :otp_keys_column, :key
    auth_value_method :otp_keys_id_column, :id
    auth_value_method :otp_keys_failures_column, :num_failures
    auth_value_method :otp_keys_table, :account_otp_keys
    auth_value_method :otp_keys_last_use_column, :last_use
    translatable_method :otp_provisioning_uri_label, 'Provisioning URL'
    translatable_method :otp_secret_label, 'Secret'
    auth_value_method :otp_setup_param, 'otp_secret'
    auth_value_method :otp_setup_raw_param, 'otp_raw_secret'
    translatable_method :otp_auth_form_footer, ''

    auth_cached_method :otp_key
    auth_cached_method :otp
    private :otp

    auth_value_methods(
      :otp_issuer,
      :otp_keys_use_hmac?
    )

    auth_methods(
      :otp_available?,
      :otp_exists?,
      :otp_last_use,
      :otp_locked_out?,
      :otp_new_secret,
      :otp_provisioning_name,
      :otp_provisioning_uri,
      :otp_qr_code,
      :otp_record_authentication_failure,
      :otp_remove,
      :otp_remove_auth_failures,
      :otp_update_last_use,
      :otp_valid_code?,
      :otp_valid_key?
    )

    auth_private_methods(
      :otp_add_key,
      :otp_tmp_key,
      :otp_valid_code_for_old_secret
    )

    internal_request_method :otp_setup_params
    internal_request_method :otp_setup
    internal_request_method :otp_auth
    internal_request_method :valid_otp_auth?
    internal_request_method :otp_disable

    route(:otp_auth) do |r|
      require_login
      require_account_session
      require_two_factor_not_authenticated('totp')
      require_otp_setup

      if otp_locked_out?
        set_response_error_reason_status(:otp_locked_out, lockout_error_status)
        set_redirect_error_flash otp_lockout_error_flash
        redirect otp_lockout_redirect
      end

      before_otp_auth_route

      r.get do
        otp_auth_view
      end

      r.post do
        if otp_valid_code?(param(otp_auth_param)) && otp_update_last_use
          before_otp_authentication
          two_factor_authenticate('totp')
        end

        otp_record_authentication_failure
        after_otp_authentication_failure
        set_response_error_reason_status(:invalid_otp_auth_code, invalid_key_error_status)
        set_field_error(otp_auth_param, otp_invalid_auth_code_message)
        set_error_flash otp_auth_error_flash
        otp_auth_view
      end
    end

    route(:otp_setup) do |r|
      require_account

      if otp_exists?
        set_redirect_error_flash otp_already_setup_error_flash
        redirect otp_already_setup_redirect
      end

      before_otp_setup_route

      r.get do
        otp_tmp_key(otp_new_secret)
        otp_setup_view
      end

      r.post do
        secret = param(otp_setup_param)
        catch_error do
          unless otp_valid_key?(secret)
            otp_tmp_key(otp_new_secret)
            throw_error_reason(:invalid_otp_secret, invalid_field_error_status, otp_setup_param, otp_invalid_secret_message)
          end

          if otp_keys_use_hmac?
            otp_tmp_key(param(otp_setup_raw_param))
          else
            otp_tmp_key(secret)
          end

          unless two_factor_password_match?(param(password_param))
            throw_error_reason(:invalid_password, invalid_password_error_status, password_param, invalid_password_message)
          end

          unless otp_valid_code?(param(otp_auth_param))
            throw_error_reason(:invalid_otp_auth_code, invalid_key_error_status, otp_auth_param, otp_invalid_auth_code_message)
          end

          transaction do
            before_otp_setup
            otp_add_key
            unless two_factor_authenticated?
              two_factor_update_session('totp')
            end
            after_otp_setup
          end
          otp_setup_response
        end

        set_error_flash otp_setup_error_flash
        otp_setup_view
      end
    end

    route(:otp_disable) do |r|
      require_account
      require_otp_setup
      before_otp_disable_route

      r.get do
        otp_disable_view
      end

      r.post do
        if two_factor_password_match?(param(password_param))
          transaction do
            before_otp_disable
            otp_remove
            if two_factor_login_type_match?('totp')
              two_factor_remove_session('totp')
            end
            after_otp_disable
          end
          otp_disable_response
        end

        set_response_error_reason_status(:invalid_password, invalid_password_error_status)
        set_field_error(password_param, invalid_password_message)
        set_error_flash otp_disable_error_flash
        otp_disable_view
      end
    end

    def two_factor_remove
      super
      otp_remove
    end

    def two_factor_remove_auth_failures
      super
      otp_remove_auth_failures
    end

    def require_otp_setup
      unless otp_exists?
        set_redirect_error_status(two_factor_not_setup_error_status)
        set_error_reason :two_factor_not_setup
        set_redirect_error_flash two_factor_not_setup_error_flash
        redirect two_factor_need_setup_redirect
      end
    end

    def otp_available?
      otp_exists? && !otp_locked_out?
    end

    def otp_exists?
      !otp_key.nil?
    end

    def otp_valid_code?(ot_pass)
      if _otp_valid_code?(ot_pass, otp)
        true
      elsif hmac_secret_rotation? && _otp_valid_code?(ot_pass, _otp_for_key(otp_hmac_old_secret(otp_key)))
        _otp_valid_code_for_old_secret
        true
      else
        false
      end
    end

    def _otp_valid_code?(ot_pass, otp)
      return false unless otp_exists?
      ot_pass = ot_pass.gsub(/\s+/, '')
      if drift = otp_drift
        if otp.respond_to?(:verify_with_drift)
          # :nocov:
          otp.verify_with_drift(ot_pass, drift)
          # :nocov:
        else
          otp.verify(ot_pass, :drift_behind=>drift, :drift_ahead=>drift)
        end
      else
        otp.verify(ot_pass)
      end
    end

    def otp_remove
      otp_key_ds.delete
      @otp_key = nil
    end

    def otp_add_key
      _otp_add_key(otp_key)
      super if defined?(super)
    end

    def otp_update_last_use
      otp_key_ds.
        where(Sequel.date_add(otp_keys_last_use_column, :seconds=>_otp_interval) < Sequel::CURRENT_TIMESTAMP).
        update(otp_keys_last_use_column=>Sequel::CURRENT_TIMESTAMP) == 1
    end

    def otp_last_use
      convert_timestamp(otp_key_ds.get(otp_keys_last_use_column))
    end

    def otp_record_authentication_failure
      otp_key_ds.update(otp_keys_failures_column=>Sequel.identifier(otp_keys_failures_column) + 1)
    end

    def otp_remove_auth_failures
      otp_key_ds.update(otp_keys_failures_column=>0)
    end

    def otp_locked_out?
      otp_key_ds.get(otp_keys_failures_column) >= otp_auth_failures_limit
    end

    def otp_provisioning_uri
      otp.provisioning_uri(otp_provisioning_name)
    end

    def otp_issuer
      domain
    end

    def otp_provisioning_name
      account[login_column]
    end

    def otp_qr_code
      svg = RQRCode::QRCode.new(otp_provisioning_uri).as_svg(:module_size=>8, :viewbox=>true, :use_path=>true, :fill=>"fff")
      svg.sub(/\A<\?xml version="1\.0" standalone="yes"\?>/, '')
    end

    def otp_user_key
      @otp_user_key ||= if otp_keys_use_hmac?
        otp_hmac_secret(otp_key)
      else
        otp_key
      end
    end

    def otp_keys_use_hmac?
      !!hmac_secret
    end

    def possible_authentication_methods
      methods = super
      methods << 'totp' if otp_exists? && !@otp_tmp_key
      methods
    end

    private

    def _two_factor_auth_links
      links = super
      links << [20, otp_auth_path, otp_auth_link_text] if show_otp_auth_link?
      links
    end

    def _two_factor_setup_links
      links = super
      links << [20, otp_setup_path, otp_setup_link_text] unless otp_exists?
      links
    end

    def _two_factor_remove_links
      links = super
      links << [20, otp_disable_path, otp_disable_link_text] if otp_exists?
      links
    end

    def _two_factor_remove_all_from_session
      two_factor_remove_session('totp')
      super
    end

    def clear_cached_otp
      remove_instance_variable(:@otp) if defined?(@otp)
    end

    def otp_tmp_key(secret)
      _otp_tmp_key(secret)
      clear_cached_otp
    end

    def otp_hmac_secret(key)
      base32_encode(compute_raw_hmac(ROTP::Base32.decode(key)), key.bytesize)
    end

    def otp_hmac_old_secret(key)
      base32_encode(compute_raw_hmac_with_secret(ROTP::Base32.decode(key), hmac_old_secret), key.bytesize)
    end

    def otp_valid_key?(secret)
      return false unless secret =~ /\A([a-z2-7]{16}|[a-z2-7]{32})\z/
      if otp_keys_use_hmac?
        # Purposely do not allow creating new OTPs with old secrets,
        # since OTP rotation is difficult.  The user will get shown
        # the same page with an updated secret, which they can submit
        # to setup OTP.
        timing_safe_eql?(otp_hmac_secret(param(otp_setup_raw_param)), secret)
      else
        true
      end
    end

    if ROTP::Base32.respond_to?(:random_base32)
      def otp_new_secret
        ROTP::Base32.random_base32.downcase
      end
    else
      # :nocov:
      def otp_new_secret
        ROTP::Base32.random.downcase
      end
      # :nocov:
    end

    def base32_encode(data, length)
      chars = 'abcdefghijklmnopqrstuvwxyz234567'
      length.times.map{|i|chars[data[i].ord % 32]}.join
    end

    def _otp_tmp_key(secret)
      @otp_tmp_key = true
      @otp_user_key = nil
      @otp_key = secret
    end

    def _otp_interval
      otp_interval || 30
    end

    # Called for valid OTP codes for old secrets
    def _otp_valid_code_for_old_secret
    end

    def _otp_add_key(secret)
      # Uniqueness errors can't be handled here, as we can't be sure the secret provided
      # is the same as the current secret.
      otp_key_ds.insert(otp_keys_id_column=>session_value, otp_keys_column=>secret)
    end

    def _otp_key
      @otp_user_key = nil
      otp_key_ds.get(otp_keys_column)
    end

    def _otp_for_key(key)
      otp_class.new(key, :issuer=>otp_issuer, :digits=>otp_digits, :interval=>otp_interval)
    end

    def _otp
      _otp_for_key(otp_user_key)
    end

    def otp_key_ds
      db[otp_keys_table].where(otp_keys_id_column=>session_value)
    end

    def show_otp_auth_link?
      otp_available?
    end

    def use_date_arithmetic?
      true
    end
  end
end
