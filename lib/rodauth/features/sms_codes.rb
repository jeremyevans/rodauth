module Rodauth
  SmsCodes = Feature.define(:sms_codes) do
    depends :two_factor_base

    additional_form_tags 'sms_auth'
    additional_form_tags 'sms_confirm'
    additional_form_tags 'sms_disable'
    additional_form_tags 'sms_request'
    additional_form_tags 'sms_setup'

    before 'sms_auth'
    before 'sms_confirm'
    before 'sms_disable'
    before 'sms_request'
    before 'sms_setup'

    after 'sms_confirm'
    after 'sms_disable'
    after 'sms_failure'
    after 'sms_request'
    after 'sms_setup'

    button 'Authenticate via SMS Code', 'sms_auth'
    button 'Confirm SMS Backup Number', 'sms_confirm'
    button 'Disable Backup SMS Authentication', 'sms_disable'
    button 'Send SMS Code', 'sms_request'
    button 'Setup SMS Backup Number', 'sms_setup'

    error_flash "Error authenticating via SMS code.", 'sms_invalid_code'
    error_flash "Error disabling SMS authentication", 'sms_disable'
    error_flash "Error setting up SMS authentication", 'sms_setup'
    error_flash "Invalid or out of date SMS confirmation code used, must setup SMS authentication again.", 'sms_invalid_confirmation_code'
    error_flash "No current SMS code for this account", 'no_current_sms_code'
    error_flash "SMS authentication has been locked out.", 'sms_lockout'

    notice_flash "SMS authentication code has been sent.", 'sms_request'
    notice_flash "SMS authentication has already been setup.", 'sms_already_setup'
    notice_flash "SMS authentication has been disabled.", 'sms_disable'
    notice_flash "SMS authentication has been setup.", 'sms_confirm'
    notice_flash "SMS authentication has not been setup yet.", 'sms_not_setup'
    notice_flash "SMS authentication needs confirmation.", 'sms_needs_confirmation'

    redirect :sms_already_setup
    redirect :sms_confirm
    redirect :sms_disable
    redirect(:sms_auth){"#{prefix}/#{sms_auth_route}"}
    redirect(:sms_needs_confirmation){"#{prefix}/#{sms_confirm_route}"}
    redirect(:sms_needs_setup){"#{prefix}/#{sms_setup_route}"}
    redirect(:sms_request){"#{prefix}/#{sms_request_route}"}

    route "sms-auth", "sms_auth"
    route "sms-confirm", "sms_confirm"
    route "sms-disable", "sms_disable"
    route "sms-request", "sms_request"
    route "sms-setup", "sms_setup"

    view 'sms-auth', 'Authenticate via SMS Code', 'sms_auth'
    view 'sms-confirm', 'Confirm SMS Backup Number', 'sms_confirm'
    view 'sms-disable', 'Disable Backup SMS Authentication', 'sms_disable'
    view 'sms-request', 'Send SMS Code', 'sms_request'
    view 'sms-setup', 'Setup SMS Backup Number', 'sms_setup'

    auth_value_method :sms_auth_code_length, 6
    auth_value_method :sms_code_allowed_seconds, 300
    auth_value_method :sms_code_column, :code
    auth_value_method :sms_code_label, 'SMS Code'
    auth_value_method :sms_code_param, 'sms_code'
    auth_value_method :sms_codes_table, :account_sms_codes
    auth_value_method :sms_confirm_code_length, 12
    auth_value_method :sms_failure_limit, 5
    auth_value_method :sms_failures_column, :num_failures
    auth_value_method :sms_id_column, :id
    auth_value_method :sms_invalid_code_message, "invalid SMS code"
    auth_value_method :sms_invalid_phone_message, "invalid SMS phone number"
    auth_value_method :sms_issued_at_column, :code_issued_at
    auth_value_method :sms_phone_column, :phone_number
    auth_value_method :sms_phone_label, 'Phone Number'
    auth_value_method :sms_phone_min_length, 7
    auth_value_method :sms_phone_param, 'sms_phone'

    auth_value_methods(
      :sms_lockout_redirect,
      :sms_codes_primary?
    )

    auth_methods(
      :sms_auth_message,
      :sms_available?,
      :sms_code_issued_at,
      :sms_code_match?,
      :sms_confirm_message,
      :sms_confirmation_match?,
      :sms_current_auth?,
      :sms_disable,
      :sms_failures,
      :sms_locked_out?,
      :sms_needs_confirmation?,
      :sms_new_auth_code,
      :sms_new_confirm_code,
      :sms_normalize_phone,
      :sms_record_failure,
      :sms_remove_failures,
      :sms_send,
      :sms_set_code,
      :sms_setup,
      :sms_setup?,
      :sms_valid_phone?
    )

    self::ROUTE_BLOCK = proc do |r, auth|
      r.is auth.sms_request_route do
        auth.require_login
        auth.require_account_session
        auth.require_two_factor_not_authenticated
        auth.require_sms_available
        auth._before_sms_request

        r.get do
          auth.sms_request_view
        end

        r.post do
          auth.transaction do
            auth.sms_send_auth_code
            auth._after_sms_request
          end
          
          auth.set_notice_flash auth.sms_request_notice_flash
          r.redirect auth.sms_auth_redirect
        end
      end

      r.is auth.sms_auth_route do
        auth.require_login
        auth.require_account_session
        auth.require_two_factor_not_authenticated
        auth.require_sms_available

        unless auth.sms_current_auth?
          if auth.sms_code
            auth.sms_set_code(nil)
          end
          auth.set_redirect_error_flash auth.no_current_sms_code_error_flash
          r.redirect auth.sms_request_redirect
        end

        auth._before_sms_auth

        r.get do
          auth.sms_auth_view
        end

        r.post do
          auth.transaction do
            if auth.sms_code_match?(auth.param(auth.sms_code_param))
              auth.sms_remove_failures
              auth.two_factor_authenticate(:sms_code)
            else
              auth.sms_record_failure
              auth._after_sms_failure
            end
          end

          @sms_code_error = auth.sms_invalid_code_message
          auth.set_error_flash auth.sms_invalid_code_error_flash
          auth.sms_auth_view
        end
      end

      r.is auth.sms_setup_route do
        auth.require_account
        unless auth.sms_codes_primary?
          auth.require_two_factor_setup
          auth.require_two_factor_authenticated
        end
        auth.require_sms_not_setup

        if auth.sms_needs_confirmation?
          auth.set_notice_flash auth.sms_needs_confirmation_notice_flash
          r.redirect auth.sms_needs_confirmation_redirect
        end

        auth._before_sms_setup

        r.get do
          auth.sms_setup_view
        end

        r.post do
          auth.catch_error do
            unless auth.two_factor_password_match?(auth.param(auth.password_param))
              auth.throw_error{@password_error = auth.invalid_password_message}
            end

            phone = auth.sms_normalize_phone(auth.param(auth.sms_phone_param))

            unless auth.sms_valid_phone?(phone)
              auth.throw_error{@sms_phone_error = auth.sms_invalid_phone_message}
            end

            auth.transaction do
              auth.sms_setup(phone)
              auth.sms_send_confirm_code
              auth._after_sms_setup
            end

            auth.set_notice_flash auth.sms_needs_confirmation_notice_flash
            r.redirect auth.sms_needs_confirmation_redirect
          end

          auth.set_error_flash auth.sms_setup_error_flash
          auth.sms_setup_view
        end
      end

      r.is auth.sms_confirm_route do
        auth.require_account
        unless auth.sms_codes_primary?
          auth.require_two_factor_setup
          auth.require_two_factor_authenticated
        end
        auth.require_sms_not_setup
        auth._before_sms_confirm

        r.get do
          auth.sms_confirm_view
        end

        r.post do
          if auth.sms_confirmation_match?(auth.param(auth.sms_code_param))
            auth.transaction do
              auth.sms_confirm
              auth._after_sms_confirm
              if auth.sms_codes_primary?
                auth.two_factor_authenticate(:sms_code)
              end
            end

            auth.set_notice_flash auth.sms_confirm_notice_flash
            r.redirect auth.sms_confirm_redirect
          end

          auth.sms_confirm_failure
          auth.set_redirect_error_flash auth.sms_invalid_confirmation_code_error_flash
          r.redirect auth.sms_needs_setup_redirect
        end
      end

      r.is auth.sms_disable_route do
        auth.require_account
        auth.require_sms_setup
        auth._before_sms_disable

        r.get do
          auth.sms_disable_view
        end

        r.post do
          if auth.two_factor_password_match?(auth.param(auth.password_param))
            auth.sms_disable
            if auth.sms_codes_primary?
              auth.two_factor_remove_session
            end
            auth.set_notice_flash auth.sms_disable_notice_flash
            r.redirect auth.sms_disable_redirect
          end

          @password_error = auth.invalid_password_message
          auth.set_error_flash auth.sms_disable_error_flash
          auth.sms_disable_view
        end
      end

    end

    def two_factor_need_setup_redirect
      super || (sms_needs_setup_redirect if sms_codes_primary?)
    end

    def two_factor_auth_required_redirect
      super || (sms_request_redirect if sms_codes_primary? && sms_available?)
    end

    def two_factor_auth_fallback_redirect
      sms_available? ? sms_request_redirect : super
    end

    def two_factor_remove
      super
      sms_disable
    end

    def two_factor_remove_auth_failures
      super
      sms_remove_failures
    end

    def two_factor_authentication_setup?
      super || (sms_codes_primary? && sms_setup?)
    end

    def otp_auth_form_footer
      "#{super if defined?(super)}#{"<p><a href=\"#{sms_request_route}\">Authenticate using SMS code</a></p>" if sms_available?}"
    end

    def otp_lockout_redirect
      if sms_available?
        sms_request_redirect
      else
        super if defined?(super)
      end
    end

    def otp_lockout_error_flash
      msg = super if defined?(super)
      if sms_available?
         msg = "#{msg} Can use SMS code to unlock."
      end
      msg
    end

    def otp_remove
      super if defined?(super)
      unless sms_codes_primary?
        sms_disable
      end
    end

    def require_sms_setup
      unless sms_setup?
        set_notice_flash sms_not_setup_notice_flash
        request.redirect sms_needs_setup_redirect
      end
    end

    def require_sms_not_setup
      if sms_setup?
        set_notice_flash sms_already_setup_notice_flash
        request.redirect sms_already_setup_redirect
      end
    end

    def require_sms_available
      require_sms_setup

      if sms_locked_out?
        set_redirect_error_flash sms_lockout_error_flash
        request.redirect sms_lockout_redirect
      end
    end

    def sms_code_match?(code)
      return false unless sms_current_auth?
      timing_safe_eql?(code, sms_code)
    end

    def sms_confirmation_match?(code)
      sms_needs_confirmation? && sms_code_match?(code)
    end

    def sms_disable
      sms_ds.delete
      super if defined?(super)
    end

    def sms_confirm_failure
      sms_ds.delete
    end

    def sms_setup(phone_number)
      # Cannot handle uniqueness violation here, as the phone number given may not match the
      # one in the table.
      sms_invalidate_cache{sms_ds.insert(sms_id_column=>session_value, sms_phone_column=>phone_number)}
    end

    def sms_remove_failures
      sms_invalidate_cache{sms_ds.update(sms_failures_column => 0, sms_code_column=>nil)}
    end

    def sms_confirm
      sms_remove_failures
      super if defined?(super)
    end

    def sms_send_auth_code
      code = sms_new_auth_code
      sms_set_code(code)
      sms_send(sms_phone, sms_auth_message(code))
    end

    def sms_send_confirm_code
      code = sms_new_confirm_code
      sms_set_code(code)
      sms_send(sms_phone, sms_confirm_message(code))
    end

    def sms_normalize_phone(phone)
      phone.to_s.gsub(/\D+/, '')
    end

    def sms_valid_phone?(phone)
      phone.length >= sms_phone_min_length
    end

    def sms_lockout_redirect
      _two_factor_auth_required_redirect
    end

    def sms_auth_message(code)
      "SMS authentication code for #{request.host} is #{code}"
    end

    def sms_confirm_message(code)
      "SMS confirmation code for #{request.host} is #{code}"
    end

    def sms_set_code(code)
     sms_invalidate_cache{sms_ds.update(sms_code_column=>code, sms_issued_at_column=>Sequel::CURRENT_TIMESTAMP)}
    end

    def sms_record_failure
      sms_invalidate_cache{sms_ds.update(sms_failures_column=>Sequel.expr(sms_failures_column)+1)}
    end

    def sms_new_auth_code
      SecureRandom.random_number(10**sms_auth_code_length).to_s.rjust(sms_auth_code_length, "0")
    end

    def sms_new_confirm_code
      SecureRandom.random_number(10**sms_confirm_code_length).to_s.rjust(sms_confirm_code_length, "0")
    end

    def sms_phone
      sms[sms_phone_column]
    end

    def sms_code
      sms[sms_code_column]
    end

    def sms_code_issued_at
      convert_timestamp(sms[sms_issued_at_column])
    end

    def sms_failures
      sms[sms_failures_column]
    end

    def sms_setup?
      return false unless sms
      !sms_needs_confirmation?
    end

    def sms_needs_confirmation?
      sms && sms_failures.nil?
    end

    def sms_available?
      sms && !sms_needs_confirmation? && !sms_locked_out?
    end

    def sms_locked_out?
      sms_failures >= sms_failure_limit
    end

    def sms_current_auth?
      sms_code && sms_code_issued_at + sms_code_allowed_seconds > Time.now
    end

    def sms_send(phone, message)
      raise NotImplementedError, "sms_send needs to be defined in the Rodauth configuration for SMS sending to work"
    end

    def sms_codes_primary?
      !features.include?(:otp)
    end

    private

    def sms
      return @sms if defined?(@sms)
      @sms = sms_ds.first
    end

    def sms_invalidate_cache
      yield
    ensure
      remove_instance_variable(:@sms) if instance_variable_defined?(:@sms)
    end
    
    def sms_ds
      db[sms_codes_table].where(sms_id_column=>session_value)
    end
  end
end
