require 'rotp'
require 'rqrcode'

module Rodauth
  OTP = Feature.define(:otp) do
    additional_form_tags 'otp_disable'
    additional_form_tags 'otp_auth'
    additional_form_tags 'otp_setup'

    after 'otp_authentication'
    after 'otp_authentication_failure'
    after 'otp_disable'
    after 'otp_setup'

    before 'otp_authentication'
    before 'otp_setup'
    before 'otp_disable'

    button 'Authenticate via 2nd Factor', 'otp_auth'
    button 'Disable Two Factor Authentication', 'otp_disable'
    button 'Setup Two Factor Authentication', 'otp_setup'

    error_flash "Authentication code use locked out due to numerous failures.", 'otp_lockout'
    error_flash "Error disabling up two factor authentication", 'otp_disable'
    error_flash "Error logging in via two factor authentication", 'otp_auth'
    error_flash "Error setting up two factor authentication", 'otp_setup'

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
    redirect :otp_locked_out
    redirect(:otp_need_setup){"#{prefix}/#{otp_setup_route}"}
    redirect(:otp_auth_required){"#{prefix}/#{otp_auth_route}"}

    view 'otp-disable', 'Disable Two Factor Authentication', 'otp_disable'
    view 'otp-auth', 'Enter Authentication Code', 'otp_auth'
    view 'otp-setup', 'Setup Two Factor Authentication', 'otp_setup'

    route 'otp', 'otp_base'

    auth_value_method :otp_auth_failures_id_column, :id
    auth_value_method :otp_auth_failures_limit, 5
    auth_value_method :otp_auth_failures_number_column, :number
    auth_value_method :otp_auth_failures_table, :account_otp_auth_failures
    auth_value_method :otp_auth_form_footer, ""
    auth_value_method :otp_auth_label, 'Authentication Code'
    auth_value_method :otp_auth_param, 'otp'
    auth_value_method :otp_invalid_auth_code_message, "Invalid authentication code"
    auth_value_method :otp_keys_column, :key
    auth_value_method :otp_keys_id_column, :id
    auth_value_method :otp_keys_table, :account_otp_keys
    auth_value_method :otp_keys_last_use_column, :last_use
    auth_value_method :otp_modifications_require_password?, true
    auth_value_method :otp_session_key, :authenticated_via_otp
    auth_value_method :otp_setup_param, 'otp_secret'
    auth_value_method :otp_setup_session_key, :otp_setup

    auth_value_methods(
      :otp_auth_route,
      :otp_class,
      :otp_disable_route,
      :otp_issuer,
      :otp_setup_route
    )

    auth_methods(
      :otp_add_key,
      :otp_exists?,
      :otp_new_secret,
      :otp,
      :otp_authenticated?,
      :otp_key,
      :otp_locked_out?,
      :otp_provisioning_name,
      :otp_provisioning_uri,
      :otp_qr_code,
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

    self::ROUTE_BLOCK = proc do |r, auth|
      r.is auth.otp_auth_route do
        auth.require_otp_not_authenticated
        auth._before_otp_authentication

        if auth.otp_locked_out?
          auth.set_redirect_error_flash auth.otp_lockout_error_flash
          r.redirect auth.otp_locked_out_redirect
        end

        r.get do
          auth.otp_auth_view
        end

        r.post do
          if auth.otp_valid_code?(auth.param(auth.otp_auth_param))
            auth.otp_remove_auth_failures
            auth.successful_otp_authentication
          end

          auth.otp_record_authentication_failure
          auth._after_otp_authentication_failure
          @otp_error = auth.otp_invalid_auth_code_message
          auth.set_error_flash auth.otp_auth_error_flash
          auth.otp_auth_view
        end
      end

      r.is auth.otp_setup_route do
        auth.require_account
        auth._before_otp_setup

        if auth.otp_exists?
          auth.set_notice_flash auth.otp_already_setup_notice_flash
          r.redirect auth.otp_auth_redirect
        end

        r.get do
          auth.otp_tmp_key(auth.otp_new_secret)
          auth.otp_setup_view
        end

        r.post do
          secret = auth.param(auth.otp_setup_param)
          next unless auth.otp_valid_key?(secret)
          auth.otp_tmp_key(secret)

          if auth.otp_password_match?(auth.param(auth.password_param))
            if auth.otp_valid_code?(auth.param(auth.otp_auth_param))
              auth.transaction do
                auth.otp_add_key(secret)
                auth.otp_update_last_use
                auth.otp_update_session
                auth._after_otp_setup
              end
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
        auth.require_account
        auth.require_otp
        auth._before_otp_disable

        r.get do
          auth.otp_disable_view
        end

        r.post do
          if auth.otp_password_match?(auth.param(auth.password_param))
            auth.transaction do
              auth.otp_remove
              auth.otp_remove_session
              auth._after_otp_disable
            end
            auth.set_notice_flash auth.otp_disable_notice_flash
            r.redirect auth.otp_disable_redirect
          end

          @password_error = auth.invalid_password_message
          auth.set_error_flash auth.otp_disable_error_flash
          auth.otp_disable_view
        end
      end
    end

    def authenticated?
      super
      otp_authenticated? if has_otp?
    end

    def require_authentication
      super
      require_otp_authenticated if has_otp?
    end
    
    def successful_otp_authentication
      otp_update_session
      otp_update_last_use
      _after_otp_authentication
      set_notice_flash otp_auth_notice_flash
      request.redirect otp_auth_redirect
    end

    def require_otp
      require_login
      require_account_session

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
    
    def otp_valid_code?(ot_pass)
      if otp_exists?
        _otp.verify(ot_pass)
      end
    end

    def otp_remove
      otp_key_ds.delete
      otp_remove_auth_failures
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
      # Uniqueness errors can't be handled here, as we can't be sure the secret provided
      # is the same as the current secret.
      otp_key_ds.insert(otp_keys_id_column=>session_value, otp_keys_column=>secret)
      session[otp_setup_session_key] = true
      @otp_key = secret
    end

    def otp_update_last_use
      otp_key_ds.update(otp_keys_last_use_column=>Sequel::CURRENT_TIMESTAMP)
    end

    def otp_record_authentication_failure
      ds = otp_auth_failures_ds
      if ds.update(otp_auth_failures_number_column=>Sequel.identifier(otp_auth_failures_number_column) + 1) == 0
        # Ignoring the violation is safe here.  It may allow slightly more than otp_auth_failures_limit
        # invalid OTP authentications before lockout, but allowing a few extra is OK if the race is lost.
        ignore_uniqueness_violation{ds.insert(otp_auth_failures_id_column=>session_value)}
      end
    end

    def otp_remove_auth_failures
      otp_auth_failures_ds.delete
    end

    def otp_locked_out?
      failures = otp_auth_failures_ds.get(otp_auth_failures_number_column) || 0
      failures >= otp_auth_failures_limit
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
  end
end
