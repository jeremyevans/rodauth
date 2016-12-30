# frozen-string-literal: true

require 'rotp'
require 'rqrcode'

module Rodauth
  Otp = Feature.define(:otp) do
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
    before 'otp_authentication_route'
    before 'otp_setup_route'
    before 'otp_disable_route'

    button 'Authenticate via 2nd Factor', 'otp_auth'
    button 'Disable Two Factor Authentication', 'otp_disable'
    button 'Setup Two Factor Authentication', 'otp_setup'

    error_flash "Error disabling up two factor authentication", 'otp_disable'
    error_flash "Error logging in via two factor authentication", 'otp_auth'
    error_flash "Error setting up two factor authentication", 'otp_setup'
    error_flash "You have already setup two factor authentication", :otp_already_setup

    notice_flash "Two factor authentication has been disabled", 'otp_disable'
    notice_flash "Two factor authentication is now setup", 'otp_setup'

    redirect :otp_disable
    redirect :otp_already_setup
    redirect :otp_setup

    view 'otp-disable', 'Disable Two Factor Authentication', 'otp_disable'
    view 'otp-auth', 'Enter Authentication Code', 'otp_auth'
    view 'otp-setup', 'Setup Two Factor Authentication', 'otp_setup'

    auth_value_method :otp_auth_failures_limit, 5
    auth_value_method :otp_auth_label, 'Authentication Code'
    auth_value_method :otp_auth_param, 'otp'
    auth_value_method :otp_class, ROTP::TOTP
    auth_value_method :otp_digits, nil
    auth_value_method :otp_drift, nil
    auth_value_method :otp_interval, nil
    auth_value_method :otp_invalid_auth_code_message, "Invalid authentication code"
    auth_value_method :otp_invalid_secret_message, "invalid secret"
    auth_value_method :otp_keys_column, :key
    auth_value_method :otp_keys_id_column, :id
    auth_value_method :otp_keys_failures_column, :num_failures
    auth_value_method :otp_keys_table, :account_otp_keys
    auth_value_method :otp_keys_last_use_column, :last_use
    auth_value_method :otp_setup_param, 'otp_secret'

    auth_cached_method :otp_key
    auth_cached_method :otp
    private :otp

    auth_value_methods(
      :otp_auth_form_footer,
      :otp_issuer,
      :otp_lockout_error_flash,
      :otp_lockout_redirect
    )

    auth_methods(
      :otp,
      :otp_exists?,
      :otp_key,
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
      :otp_tmp_key
    )

    route(:otp_auth) do |r|
      require_login
      require_account_session
      require_two_factor_not_authenticated
      require_otp_setup

      if otp_locked_out?
        set_response_error_status(lockout_error_status)
        set_redirect_error_flash otp_lockout_error_flash
        redirect otp_lockout_redirect
      end

      before_otp_authentication_route

      r.get do
        otp_auth_view
      end

      r.post do
        if otp_valid_code?(param(otp_auth_param)) && otp_update_last_use
          before_otp_authentication
          two_factor_authenticate(:totp)
        end

        otp_record_authentication_failure
        after_otp_authentication_failure
        set_response_error_status(invalid_key_error_status)
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
            throw_error_status(invalid_field_error_status, otp_setup_param, otp_invalid_secret_message)
          end
          otp_tmp_key(secret)

          unless two_factor_password_match?(param(password_param))
            throw_error_status(invalid_password_error_status, password_param, invalid_password_message)
          end

          unless otp_valid_code?(param(otp_auth_param))
            throw_error_status(invalid_key_error_status, otp_auth_param, otp_invalid_auth_code_message)
          end

          transaction do
            before_otp_setup
            otp_add_key
            two_factor_update_session(:totp)
            after_otp_setup
          end
          set_notice_flash otp_setup_notice_flash
          redirect otp_setup_redirect
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
            two_factor_remove_session
            after_otp_disable
          end
          set_notice_flash otp_disable_notice_flash
          redirect otp_disable_redirect
        end

        set_response_error_status(invalid_password_error_status)
        set_field_error(password_param, invalid_password_message)
        set_error_flash otp_disable_error_flash
        otp_disable_view
      end
    end

    def two_factor_authentication_setup?
      super || otp_exists?
    end

    def two_factor_need_setup_redirect
      "#{prefix}/#{otp_setup_route}"
    end

    def two_factor_auth_required_redirect
      "#{prefix}/#{otp_auth_route}"
    end

    def two_factor_remove
      super
      otp_remove
    end

    def two_factor_remove_auth_failures
      super
      otp_remove_auth_failures
    end

    def otp_auth_form_footer
      super if defined?(super)
    end

    def otp_lockout_redirect
      return super if defined?(super)
      default_redirect
    end

    def otp_lockout_error_flash
      "Authentication code use locked out due to numerous failures.#{super if defined?(super)}"
    end

    def require_otp_setup
      unless otp_exists?
        set_redirect_error_status(two_factor_not_setup_error_status)
        set_redirect_error_flash two_factor_not_setup_error_flash
        redirect two_factor_need_setup_redirect
      end
    end

    def otp_exists?
      !otp_key.nil?
    end
    
    def otp_valid_code?(ot_pass)
      return false unless otp_exists?
      ot_pass = ot_pass.gsub(/\s+/, '')
      if drift = otp_drift
        otp.verify_with_drift(ot_pass, drift)
      else
        otp.verify(ot_pass)
      end
    end

    def otp_remove
      otp_key_ds.delete
      super if defined?(super)
    end

    def otp_add_key
      _otp_add_key(otp_key)
      super if defined?(super)
    end

    def otp_update_last_use
      otp_key_ds.
        where(Sequel.date_add(otp_keys_last_use_column, :seconds=>(otp_interval||30)) < Sequel::CURRENT_TIMESTAMP).
        update(otp_keys_last_use_column=>Sequel::CURRENT_TIMESTAMP) == 1
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
      request.host
    end

    def otp_provisioning_name
      account[login_column]
    end

    def otp_qr_code
      RQRCode::QRCode.new(otp_provisioning_uri).as_svg(:module_size=>8)
    end

    private

    def clear_cached_otp
      remove_instance_variable(:@otp) if defined?(@otp)
    end

    def otp_tmp_key(secret)
      _otp_tmp_key(secret)
      clear_cached_otp
    end

    def otp_valid_key?(secret)
      secret =~ /\A[a-z2-7]{16}\z/
    end

    def otp_new_secret
      ROTP::Base32.random_base32
    end

    def _otp_tmp_key(secret)
      @otp_key = secret
    end

    def _otp_add_key(secret)
      # Uniqueness errors can't be handled here, as we can't be sure the secret provided
      # is the same as the current secret.
      otp_key_ds.insert(otp_keys_id_column=>session_value, otp_keys_column=>secret)
    end

    def _otp_key
      otp_key_ds.get(otp_keys_column)
    end

    def _otp
      otp_class.new(otp_key, :issuer=>otp_issuer, :digits=>otp_digits, :interval=>otp_interval)
    end

    def otp_key_ds
      db[otp_keys_table].where(otp_keys_id_column=>session_value)
    end

    def use_date_arithmetic?
      true
    end
  end
end
