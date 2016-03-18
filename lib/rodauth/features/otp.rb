require 'rotp'
require 'rqrcode'

module Rodauth
  OTP = Feature.define(:otp) do
    additional_form_tags 'otp_disable'
    additional_form_tags 'otp_auth'
    additional_form_tags 'otp_recovery'
    additional_form_tags 'otp_recovery_codes'
    additional_form_tags 'otp_setup'

    after 'otp_authentication'
    after 'otp_authentication_failure'
    after 'otp_disable'
    after 'otp_setup'

    button 'Add Authentication Recovery Codes', 'otp_add_recovery_codes'
    button 'Authenticate via 2nd Factor', 'otp_auth'
    button 'Authenticate via Recovery Code', 'otp_recovery'
    button 'Disable Two Factor Authentication', 'otp_disable'
    button 'Setup Two Factor Authentication', 'otp_setup'
    button 'View Authentication Recovery Codes', 'otp_view_recovery_codes'

    error_flash "Authentication code use locked out due to numerous failures. Must use recovery code to unlock.", 'otp_lockout'
    error_flash "Error disabling up two factor authentication", 'otp_disable'
    error_flash "Error logging in via two factor authentication", 'otp_auth'
    error_flash "Error setting up two factor authentication", 'otp_setup'
    error_flash "Error logging in via recovery code.", 'otp_invalid_recovery_code'
    error_flash "Unable to add recovery codes.", 'otp_add_recovery_codes'
    error_flash "Unable to view recovery codes.", 'otp_view_recovery_codes'

    notice_flash "Additional authentication recovery codes have been added.", 'otp_recovery_codes_added'
    notice_flash "Already authenticated via 2nd factor", 'otp_already_authenticated'
    notice_flash "You have already setup two factor authentication", :otp_already_setup
    notice_flash "This account has not been setup for two factor authentication", 'otp_not_setup'
    notice_flash "Two factor authentication has been disabled", 'otp_disable'
    notice_flash "Two factor authentication is now setup", 'otp_setup'
    notice_flash "You have been authenticated via 2nd factor", 'otp_auth'
    notice_flash "You need to authenticate via 2nd factor before continuing.", 'otp_need_authentication'

    redirect :otp_already_authenticated
    redirect :otp_auth
    redirect :otp_disable
    redirect :otp_setup
    redirect(:otp_already_setup){"#{prefix}/#{otp_auth_route}"}
    redirect(:otp_recovery){"#{prefix}/#{otp_recovery_route}"}
    redirect(:otp_need_setup){"#{prefix}/#{otp_setup_route}"}
    redirect(:otp_auth_required){"#{prefix}/#{otp_auth_route}"}

    view 'otp-add-recovery-codes', 'Authentication Recovery Codes', 'otp_add_recovery_codes'
    view 'otp-disable', 'Disable Two Factor Authentication', 'otp_disable'
    view 'otp-auth', 'Enter Authentication Code', 'otp_auth'
    view 'otp-recovery', 'Enter Authentication Recovery Code', 'otp_recovery'
    view 'otp-recovery-codes', 'View Authentication Recovery Codes', 'otp_recovery_codes'
    view 'otp-setup', 'Setup Two Factor Authentication', 'otp_setup'

    require_account
    route 'otp', 'otp_base'

    auth_value_method :otp_add_recovery_codes_param, 'otp_add'
    auth_value_method :otp_auth_failures_id_column, :id
    auth_value_method :otp_auth_failures_limit, 5
    auth_value_method :otp_auth_failures_number_column, :number
    auth_value_method :otp_auth_failures_table, :account_otp_auth_failures
    auth_value_method :otp_auth_label, 'Authentication Code'
    auth_value_method :otp_auth_param, 'otp'
    auth_value_method :otp_invalid_auth_code_message, "Invalid authentication code"
    auth_value_method :otp_invalid_recovery_code_message, "Invalid recovery code"
    auth_value_method :otp_keys_column, :key
    auth_value_method :otp_keys_id_column, :id
    auth_value_method :otp_keys_table, :account_otp_keys
    auth_value_method :otp_keys_last_use_column, :last_use
    auth_value_method :otp_modifications_require_password?, true
    auth_value_method :otp_recovery_codes_limit, 16
    auth_value_method :otp_recovery_codes_column, :code
    auth_value_method :otp_recovery_codes_id_column, :id
    auth_value_method :otp_recovery_codes_label, 'Recovery Code'
    auth_value_method :otp_recovery_codes_param, 'otp_recovery_code'
    auth_value_method :otp_recovery_codes_table, :account_otp_recovery_codes
    auth_value_method :otp_session_key, :authenticated_via_otp
    auth_value_method :otp_setup_param, 'otp_secret'
    auth_value_method :otp_setup_session_key, :otp_setup

    auth_value_methods(
      :otp_class,
      :otp_issuer
    )

    auth_methods(
      :otp_add_key,
      :before_otp_authentication,
      :before_otp_setup,
      :before_otp_disable,
      :before_otp_recovery,
      :before_otp_recovery_codes,
      :otp_exists?,
      :otp_new_recovery_code,
      :otp_new_secret,
      :otp,
      :otp_add_recovery_code,
      :otp_authenticated?,
      :otp_can_add_recovery_codes?,
      :otp_disable_route,
      :otp_key,
      :otp_locked_out?,
      :otp_auth_route,
      :otp_provisioning_name,
      :otp_provisioning_uri,
      :otp_qr_code,
      :otp_recovery_code_match?,
      :otp_recovery_codes,
      :otp_recovery_codes_route,
      :otp_recovery_route,
      :otp_setup_route,
      :otp_tmp_key,
      :otp_update_last_use,
      :otp_valid_key?,
      :otp_record_authentication_failure,
      :otp_remove,
      :otp_remove_auth_failures,
      :otp_remove_session,
      :otp_update_session,
      :otp_valid_code?
    )

    feature = self
    self::ROUTE_BLOCK = proc do |r, auth|
      r.is auth.otp_auth_route do
        auth.check_before(feature)
        auth.before_otp_authentication

        auth.require_otp_not_authenticated

        if auth.otp_locked_out?
          auth.set_redirect_error_flash auth.otp_lockout_error_flash
          r.redirect auth.otp_recovery_redirect
        end

        r.get do
          auth.otp_auth_view
        end

        r.post do
          if auth.otp_valid_code?(r[auth.otp_auth_param].to_s)
            auth.otp_remove_auth_failures
            auth.successful_otp_authentication
          end

          auth.otp_record_authentication_failure
          auth.after_otp_authentication_failure
          @otp_error = auth.otp_invalid_auth_code_message
          auth.set_error_flash auth.otp_auth_error_flash
          auth.otp_auth_view
        end
      end

      r.is auth.otp_setup_route do
        auth.check_before(feature)
        auth.before_otp_setup

        if auth.otp_exists?
          auth.set_notice_flash auth.otp_already_setup_notice_flash

          if auth.otp_authenticated?
            r.redirect auth.otp_auth_redirect
          else
            r.redirect auth.otp_already_setup_redirect
          end
        end

        r.get do
          auth.otp_tmp_key(auth.otp_new_secret)
          auth.otp_setup_view
        end

        r.post do
          secret = r[auth.otp_setup_param].to_s
          next unless auth.otp_valid_key?(secret)
          auth.otp_tmp_key(secret)

          if auth.otp_password_match?(r[auth.password_param].to_s)
            if auth.otp_valid_code?(r[auth.otp_auth_param].to_s)
              auth.transaction do
                auth.otp_add_key(secret)
                auth.otp_update_last_use
              end
              auth.otp_update_session
              auth.after_otp_setup
              auth.set_notice_flash auth.otp_setup_notice_flash
              r.redirect auth.otp_setup_redirect
            else
              @otp_error = auth.otp_invalid_auth_code_message
            end
          else
            @password_error = auth.invalid_password_message
          end

          auth.set_error_flash auth.otp_setup_error_flash
          auth.otp_setup_view
        end
      end

      r.is auth.otp_disable_route do
        auth.check_before(feature)
        auth.before_otp_disable

        auth.require_otp_authenticated

        r.get do
          auth.otp_disable_view
        end

        r.post do
          if auth.otp_password_match?(r[auth.password_param].to_s)
            auth.otp_remove
            auth.otp_remove_session
            auth.after_otp_disable
            auth.set_notice_flash auth.otp_disable_notice_flash
            r.redirect auth.otp_disable_redirect
          end

          @password_error = auth.invalid_password_message
          auth.set_error_flash auth.otp_disable_error_flash
          auth.otp_disable_view
        end
      end

      r.is auth.otp_recovery_route do
        auth.check_before(feature)
        auth.before_otp_recovery

        auth.require_otp_not_authenticated

        r.get do
          auth.otp_recovery_view
        end

        r.post do
          if auth.otp_recovery_code_match?(r[auth.otp_recovery_codes_param].to_s)
            auth.otp_remove_auth_failures
            auth.successful_otp_authentication
          end

          @otp_recovery_error = auth.otp_invalid_recovery_code_message
          auth.set_error_flash auth.otp_invalid_recovery_code_error_flash

          auth.otp_recovery_view
        end
      end

      r.is auth.otp_recovery_codes_route do
        auth.check_before(feature)
        auth.before_otp_recovery_codes

        auth.require_otp_authenticated

        r.get do
          auth.otp_recovery_codes_view
        end

        r.post do
          if auth.otp_password_match?(r[auth.password_param].to_s)
            if auth.otp_can_add_recovery_codes?
              if r[auth.otp_add_recovery_codes_param]
                auth.otp_add_recovery_codes(auth.otp_recovery_codes_limit - auth._otp_recovery_codes.length)
                auth.set_notice_now_flash auth.otp_recovery_codes_added_notice_flash
              end

              @otp_add_recovery_codes = auth.otp_add_recovery_codes_button
            end

            auth.otp_add_recovery_codes_view
          else
            if r[auth.otp_add_recovery_codes_param]
              auth.set_error_flash auth.otp_add_recovery_codes_error_flash
            else
              auth.set_error_flash auth.otp_view_recovery_codes_error_flash
            end

            @password_error = auth.invalid_password_message
            auth.otp_recovery_codes_view
          end
        end
      end
    end
    
    def successful_otp_authentication
      otp_update_session
      otp_update_last_use
      after_otp_authentication
      set_notice_flash otp_auth_notice_flash
      request.redirect otp_auth_redirect
    end

    def require_otp
      unless has_otp?
        set_notice_flash otp_not_setup_notice_flash
        request.redirect otp_need_setup_redirect
      end
    end

    def require_otp_not_authenticated
      require_otp

      if otp_authenticated?
        set_notice_flash otp_already_authenticated_notice_flash
        request.redirect otp_already_authenticated_redirect
      end
    end

    def require_otp_authenticated
      require_otp

      unless otp_authenticated?
        set_notice_flash otp_need_authentication_notice_flash
        request.redirect otp_auth_required_redirect
      end
    end

    def otp_password_match?(password)
      if otp_modifications_require_password?
        password_match?(password)
      else
        true
      end
    end

    def otp_auth_route
      otp_base_route
    end

    def otp_setup_route
      "#{otp_base_route}/setup"
    end

    def otp_disable_route
      "#{otp_base_route}/disable"
    end

    def otp_recovery_route
      "#{otp_base_route}/recovery"
    end

    def otp_recovery_codes_route
      "#{otp_base_route}/recovery-codes"
    end

    def otp_authenticated?
      session[otp_session_key]
    end

    def has_otp?
      return false unless logged_in?
      session[otp_setup_session_key] = otp_exists? unless session.has_key?(otp_setup_session_key)
      session[otp_setup_session_key]
    end

    def otp_remove_session
      session.delete(otp_session_key)
      session[otp_setup_session_key] = false
    end

    def otp_exists?
      !_otp_key.nil?
    end
    
    def before_otp_authentication
      nil
    end

    def before_otp_setup
      nil
    end

    def before_otp_disable
      nil
    end

    def before_otp_recovery
      nil
    end

    def before_otp_recovery_codes
      nil
    end

    def otp_valid_code?(ot_pass)
      if otp_exists?
        _otp.verify(ot_pass)
      end
    end

    def otp_remove
      transaction do
        otp_key_ds.delete
        otp_remove_auth_failures
        otp_recovery_codes_ds.delete
      end
    end

    def otp_key
      otp_key_ds.get(otp_keys_column)
    end

    def _otp_key
      @otp_key ||= otp_key
    end

    def otp_tmp_key(secret)
      @otp_key = secret
    end

    def otp_valid_key?(secret)
      secret =~ /\A[a-z2-7]{16}\z/
    end

    def otp_add_key(secret)
      transaction do
        otp_key_ds.insert(otp_keys_id_column=>session_value, otp_keys_column=>secret)
        otp_add_recovery_codes(otp_recovery_codes_limit)
      end
      session[otp_setup_session_key] = true
      @otp_key = secret
    end

    def otp_update_last_use
      otp_key_ds.update(otp_keys_last_use_column=>Sequel::CURRENT_TIMESTAMP)
    end

    def otp_record_authentication_failure
      ds = otp_auth_failures_ds
      rows_updated = ds.update(otp_auth_failures_number_column=>Sequel.identifier(otp_auth_failures_number_column) + 1)

      if rows_updated == 0
        ds.insert(otp_auth_failures_id_column=>session_value)
      end
    end

    def otp_remove_auth_failures
      otp_auth_failures_ds.delete
    end

    def otp_locked_out?
      failures = otp_auth_failures_ds.get(otp_auth_failures_number_column) || 0
      failures >= otp_auth_failures_limit
    end

    def otp_recovery_code_match?(code)
      _otp_recovery_codes.each do |s|
        if timing_safe_eql?(code, s)
          otp_recovery_codes_ds.where(otp_recovery_codes_column=>code).delete
          return true
        end
      end
      false
    end

    def otp_can_add_recovery_codes?
      _otp_recovery_codes.length < otp_recovery_codes_limit
    end

    def otp_add_recovery_codes(number)
      return if number <= 0
      transaction do
        number.times do
          otp_add_recovery_code
        end
      end
      @otp_recovery_codes = nil
    end

    def otp_add_recovery_code
      otp_recovery_codes_ds.insert(otp_recovery_codes_id_column=>session_value, otp_recovery_codes_column=>otp_new_recovery_code)
    end

    def otp_recovery_codes
      otp_recovery_codes_ds.select_map(otp_recovery_codes_column)
    end

    def _otp_recovery_codes
      @otp_recovery_codes ||= otp_recovery_codes
    end

    def otp_new_recovery_code
      random_key
    end
    
    def otp_update_session
      session[otp_session_key] = true
    end

    def otp_class
      ROTP::TOTP
    end

    def otp
      otp_class.new(_otp_key, :issuer=>otp_issuer)
    end

    def otp_new_secret
      ROTP::Base32.random_base32
    end

    def otp_provisioning_uri
      _otp.provisioning_uri(otp_provisioning_name)
    end

    def otp_issuer
      request.host
    end

    def otp_provisioning_name
      account.send(login_column)
    end

    def otp_qr_code
      RQRCode::QRCode.new(otp_provisioning_uri).as_svg(:module_size=>8)
    end

    private

    def _otp
      @otp ||= otp
    end

    def otp_key_ds
      db[otp_keys_table].where(otp_keys_id_column=>session_value)
    end

    def otp_auth_failures_ds
      db[otp_auth_failures_table].where(otp_auth_failures_id_column=>session_value)
    end

    def otp_recovery_codes_ds
      db[otp_recovery_codes_table].where(otp_recovery_codes_id_column=>session_value)
    end

  end
end
