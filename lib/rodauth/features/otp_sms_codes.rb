module Rodauth
  OTPSMSCodes = Feature.define(:otp_sms_codes) do
    depends :otp

    additional_form_tags 'otp_sms_auth'
    additional_form_tags 'otp_sms_confirm'
    additional_form_tags 'otp_sms_disable'
    additional_form_tags 'otp_sms_request'
    additional_form_tags 'otp_sms_setup'

    before 'otp_sms_auth'
    before 'otp_sms_confirm'
    before 'otp_sms_disable'
    before 'otp_sms_request'
    before 'otp_sms_setup'

    after 'otp_sms_confirm'
    after 'otp_sms_disable'
    after 'otp_sms_failure'
    after 'otp_sms_request'
    after 'otp_sms_setup'

    button 'Authenticate via SMS Code', 'otp_sms_auth'
    button 'Confirm SMS Backup Number', 'otp_sms_confirm'
    button 'Disable Backup SMS Authentication', 'otp_sms_disable'
    button 'Send SMS Code', 'otp_sms_request'
    button 'Setup SMS Backup Number', 'otp_sms_setup'

    error_flash "Error authenticating via SMS code.", 'otp_sms_invalid_code'
    error_flash "Error disabling SMS authentication", 'otp_sms_disable'
    error_flash "Error setting up SMS authentication", 'otp_sms_setup'
    error_flash "Invalid or out of date SMS confirmation code used, must setup SMS authentication again.", 'otp_sms_invalid_confirmation_code'
    error_flash "No current SMS code for this account", 'otp_no_current_sms_code'
    error_flash "SMS authentication has been locked out.", 'otp_sms_lockout'

    notice_flash "SMS authentication code has been sent.", 'otp_sms_request'
    notice_flash "SMS authentication has already been setup.", 'otp_sms_already_setup'
    notice_flash "SMS authentication has been disabled.", 'otp_sms_disable'
    notice_flash "SMS authentication has been setup.", 'otp_sms_confirm'
    notice_flash "SMS authentication has not been setup yet.", 'otp_sms_not_setup'
    notice_flash "SMS authentication needs confirmation.", 'otp_sms_needs_confirmation'

    redirect :otp_sms_already_setup
    redirect :otp_sms_confirm
    redirect :otp_sms_disable
    redirect(:otp_sms_auth){"#{prefix}/#{otp_sms_auth_route}"}
    redirect(:otp_sms_needs_confirmation){"#{prefix}/#{otp_sms_confirm_route}"}
    redirect(:otp_sms_needs_setup){"#{prefix}/#{otp_sms_setup_route}"}
    redirect(:otp_sms_request){"#{prefix}/#{otp_sms_request_route}"}

    view 'otp-sms-auth', 'Authenticate via SMS Code', 'otp_sms_auth'
    view 'otp-sms-confirm', 'Confirm SMS Backup Number', 'otp_sms_confirm'
    view 'otp-sms-disable', 'Disable Backup SMS Authentication', 'otp_sms_disable'
    view 'otp-sms-request', 'Send SMS Code', 'otp_sms_request'
    view 'otp-sms-setup', 'Setup SMS Backup Number', 'otp_sms_setup'

    auth_value_method :otp_sms_auth_code_length, 6
    auth_value_method :otp_sms_code_allowed_seconds, 300
    auth_value_method :otp_sms_code_column, :code
    auth_value_method :otp_sms_code_label, 'SMS Code'
    auth_value_method :otp_sms_code_param, 'otp_sms_code'
    auth_value_method :otp_sms_codes_table, :account_otp_sms_codes
    auth_value_method :otp_sms_confirm_code_length, 12
    auth_value_method :otp_sms_failure_limit, 5
    auth_value_method :otp_sms_failures_column, :num_failures
    auth_value_method :otp_sms_id_column, :id
    auth_value_method :otp_sms_invalid_code_message, "invalid SMS code"
    auth_value_method :otp_sms_invalid_phone_message, "invalid SMS phone number"
    auth_value_method :otp_sms_issued_at_column, :code_issued_at
    auth_value_method :otp_sms_phone_column, :phone_number
    auth_value_method :otp_sms_phone_label, 'Phone Number'
    auth_value_method :otp_sms_phone_min_length, 7
    auth_value_method :otp_sms_phone_param, 'otp_sms_phone'

    auth_value_methods(
      :otp_sms_lockout_redirect
    )

    auth_methods(
      :otp_sms_auth_message,
      :otp_sms_auth_route,
      :otp_sms_available?,
      :otp_sms_code_issued_at,
      :otp_sms_code_match?,
      :otp_sms_confirm_message,
      :otp_sms_confirm_route,
      :otp_sms_confirmation_match?,
      :otp_sms_current_auth?,
      :otp_sms_disable,
      :otp_sms_disable_route,
      :otp_sms_failures,
      :otp_sms_locked_out?,
      :otp_sms_needs_confirmation?,
      :otp_sms_new_auth_code,
      :otp_sms_new_confirm_code,
      :otp_sms_normalize_phone,
      :otp_sms_record_failure,
      :otp_sms_remove_failures,
      :otp_sms_request_route,
      :otp_sms_send,
      :otp_sms_set_code,
      :otp_sms_setup,
      :otp_sms_setup?,
      :otp_sms_setup_route,
      :otp_sms_valid_phone?
    )

    self::ROUTE_BLOCK = proc do |r, auth|
      r.is auth.otp_sms_request_route do
        auth.require_otp_not_authenticated
        auth.require_otp_sms_available
        auth._before_otp_sms_request

        r.get do
          auth.otp_sms_request_view
        end

        r.post do
          auth.transaction do
            auth.otp_sms_send_auth_code
            auth._after_otp_sms_request
          end
          
          auth.set_notice_flash auth.otp_sms_request_notice_flash
          r.redirect auth.otp_sms_auth_redirect
        end
      end

      r.is auth.otp_sms_auth_route do
        auth.require_otp_not_authenticated
        auth.require_otp_sms_available

        unless auth.otp_sms_current_auth?
          if auth.otp_sms_code
            auth.otp_sms_set_code(nil)
          end
          auth.set_redirect_error_flash auth.otp_no_current_sms_code_error_flash
          r.redirect auth.otp_sms_request_redirect
        end

        auth._before_otp_sms_auth

        r.get do
          auth.otp_sms_auth_view
        end

        r.post do
          auth.transaction do
            if auth.otp_sms_code_match?(auth.param(auth.otp_sms_code_param))
              auth.otp_sms_remove_failures
              auth.successful_otp_authentication(:sms_code)
            else
              auth.otp_sms_record_failure
              auth._after_otp_sms_failure
            end
          end

          @otp_sms_code_error = auth.otp_sms_invalid_code_message
          auth.set_error_flash auth.otp_sms_invalid_code_error_flash
          auth.otp_sms_auth_view
        end
      end

      r.is auth.otp_sms_setup_route do
        auth.require_otp_authenticated
        auth.require_otp_sms_not_setup

        if auth.otp_sms_needs_confirmation?
          auth.set_notice_flash auth.otp_sms_needs_confirmation_notice_flash
          r.redirect auth.otp_sms_needs_confirmation_redirect
        end

        auth._before_otp_sms_setup

        r.get do
          auth.otp_sms_setup_view
        end

        r.post do
          auth.catch_error do
            unless auth.otp_password_match?(auth.param(auth.password_param))
              auth.throw_error{@password_error = auth.invalid_password_message}
            end

            phone = auth.otp_sms_normalize_phone(auth.param(auth.otp_sms_phone_param))

            unless auth.otp_sms_valid_phone?(phone)
              auth.throw_error{@otp_sms_phone_error = auth.otp_sms_invalid_phone_message}
            end

            auth.transaction do
              auth.otp_sms_setup(phone)
              auth.otp_sms_send_confirm_code
              auth._after_otp_sms_setup
            end

            auth.set_notice_flash auth.otp_sms_needs_confirmation_notice_flash
            r.redirect auth.otp_sms_needs_confirmation_redirect
          end

          auth.set_error_flash auth.otp_sms_setup_error_flash
          auth.otp_sms_setup_view
        end
      end

      r.is auth.otp_sms_confirm_route do
        auth.require_otp_authenticated
        auth.require_otp_sms_not_setup
        auth._before_otp_sms_confirm

        r.get do
          auth.otp_sms_confirm_view
        end

        r.post do
          if auth.otp_sms_confirmation_match?(auth.param(auth.otp_sms_code_param))
            auth.transaction do
              auth.otp_sms_confirm
              auth._after_otp_sms_confirm
            end

            auth.set_notice_flash auth.otp_sms_confirm_notice_flash
            r.redirect auth.otp_sms_confirm_redirect
          end

          auth.otp_sms_confirm_failure
          auth.set_redirect_error_flash auth.otp_sms_invalid_confirmation_code_error_flash
          r.redirect auth.otp_sms_needs_setup_redirect
        end
      end

      r.is auth.otp_sms_disable_route do
        auth.require_otp_authenticated
        auth.require_otp_sms_setup
        auth._before_otp_sms_disable

        r.get do
          auth.otp_sms_disable_view
        end

        r.post do
          if auth.otp_password_match?(auth.param(auth.password_param))
            auth.otp_sms_disable
            auth.set_notice_flash auth.otp_sms_disable_notice_flash
            r.redirect auth.otp_sms_disable_redirect
          end

          @password_error = auth.invalid_password_message
          auth.set_error_flash auth.otp_sms_disable_error_flash
          auth.otp_sms_disable_view
        end
      end

    end

    def otp_auth_form_footer
      "#{super}#{"<p><a href=\"#{otp_sms_request_route}\">Authenticate using SMS code</a></p>" if otp_sms_available?}"
    end

    def otp_locked_out_redirect
      if otp_sms_available?
        otp_sms_request_redirect
      else
        super
      end
    end

    def otp_lockout_error_flash
      msg = super
      if otp_sms_available?
        msg += " Can use SMS code to unlock."
      end
      msg
    end

    def otp_remove
      super
      otp_sms_ds.delete
    end

    def require_otp_sms_setup
      unless otp_sms_setup?
        set_notice_flash otp_sms_not_setup_notice_flash
        request.redirect otp_sms_needs_setup_redirect
      end
    end

    def require_otp_sms_not_setup
      if otp_sms_setup?
        set_notice_flash otp_sms_already_setup_notice_flash
        request.redirect otp_sms_already_setup_redirect
      end
    end

    def require_otp_sms_available
      require_otp_sms_setup

      if otp_sms_locked_out?
        set_redirect_error_flash otp_sms_lockout_error_flash
        request.redirect otp_sms_lockout_redirect
      end
    end

    def otp_sms_auth_route
      "#{otp_base_route}/sms-auth"
    end

    def otp_sms_confirm_route
      "#{otp_base_route}/sms-confirm"
    end

    def otp_sms_disable_route
      "#{otp_base_route}/sms-disable"
    end

    def otp_sms_request_route
      "#{otp_base_route}/sms-request"
    end

    def otp_sms_setup_route
      "#{otp_base_route}/sms-setup"
    end

    def otp_sms_code_match?(code)
      return false unless otp_sms_current_auth?
      timing_safe_eql?(code, otp_sms_code)
    end

    def otp_sms_confirmation_match?(code)
      otp_sms_needs_confirmation? && otp_sms_code_match?(code)
    end

    def otp_sms_disable
      otp_sms_ds.delete
    end
    alias otp_sms_confirm_failure otp_sms_disable

    def otp_sms_setup(phone_number)
      # Cannot handle uniqueness violation here, as the phone number given may not match the
      # one in the table.
      otp_sms_invalidate_cache{otp_sms_ds.insert(otp_sms_id_column=>session_value, otp_sms_phone_column=>phone_number)}
    end

    def otp_sms_remove_failures
      otp_sms_invalidate_cache{otp_sms_ds.update(otp_sms_failures_column => 0, otp_sms_code_column=>nil)}
    end
    alias otp_sms_confirm otp_sms_remove_failures

    def otp_sms_send_auth_code
      code = otp_sms_new_auth_code
      otp_sms_set_code(code)
      otp_sms_send(otp_sms_phone, otp_sms_auth_message(code))
    end

    def otp_sms_send_confirm_code
      code = otp_sms_new_confirm_code
      otp_sms_set_code(code)
      otp_sms_send(otp_sms_phone, otp_sms_confirm_message(code))
    end

    def otp_sms_normalize_phone(phone)
      phone.to_s.gsub(/\D+/, '')
    end

    def otp_sms_valid_phone?(phone)
      phone.length >= otp_sms_phone_min_length
    end

    def otp_sms_lockout_redirect
      otp_auth_required_redirect
    end

    def otp_sms_auth_message(code)
      "SMS authentication code for #{request.host} is #{code}"
    end

    def otp_sms_confirm_message(code)
      "SMS confirmation code for #{request.host} is #{code}"
    end

    def otp_sms_set_code(code)
     otp_sms_invalidate_cache{otp_sms_ds.update(otp_sms_code_column=>code, otp_sms_issued_at_column=>Sequel::CURRENT_TIMESTAMP)}
    end

    def otp_sms_record_failure
      otp_sms_invalidate_cache{otp_sms_ds.update(otp_sms_failures_column=>Sequel.expr(otp_sms_failures_column)+1)}
    end

    def otp_sms_new_auth_code
      SecureRandom.random_number(10**otp_sms_auth_code_length).to_s.rjust(otp_sms_auth_code_length, "0")
    end

    def otp_sms_new_confirm_code
      SecureRandom.random_number(10**otp_sms_confirm_code_length).to_s.rjust(otp_sms_confirm_code_length, "0")
    end

    def otp_sms_phone
      otp_sms[otp_sms_phone_column]
    end

    def otp_sms_code
      otp_sms[otp_sms_code_column]
    end

    def otp_sms_code_issued_at
      convert_timestamp(otp_sms[otp_sms_issued_at_column])
    end

    def otp_sms_failures
      otp_sms[otp_sms_failures_column]
    end

    def otp_sms_setup?
      return false unless otp_sms
      !otp_sms_needs_confirmation?
    end

    def otp_sms_needs_confirmation?
      otp_sms && otp_sms_failures.nil?
    end

    def otp_sms_available?
      otp_sms && !otp_sms_needs_confirmation? && !otp_sms_locked_out?
    end

    def otp_sms_locked_out?
      otp_sms_failures >= otp_sms_failure_limit
    end

    def otp_sms_current_auth?
      otp_sms_code && otp_sms_code_issued_at + otp_sms_code_allowed_seconds > Time.now
    end

    def otp_sms_send(phone, message)
      raise NotImplementedError, "otp_sms_send needs to be defined in the Rodauth configuration for SMS sending to work"
    end

    private

    def otp_sms
      return @otp_sms if defined?(@otp_sms)
      @otp_sms = otp_sms_ds.first
    end

    def otp_sms_invalidate_cache
      yield
    ensure
      remove_instance_variable(:@otp_sms) if instance_variable_defined?(:@otp_sms)
    end
    
    def otp_sms_ds
      db[otp_sms_codes_table].where(otp_sms_id_column=>session_value)
    end
  end
end
