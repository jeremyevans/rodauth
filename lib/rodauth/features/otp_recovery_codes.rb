module Rodauth
  OTPRecoveryCodes = Feature.define(:otp_recovery_codes) do
    depends :otp

    additional_form_tags 'otp_recovery'
    additional_form_tags 'otp_recovery_codes'

    before 'otp_recovery'
    before 'otp_recovery_codes'

    button 'Add Authentication Recovery Codes', 'otp_add_recovery_codes'
    button 'Authenticate via Recovery Code', 'otp_recovery'
    button 'View Authentication Recovery Codes', 'otp_view_recovery_codes'

    error_flash "Error logging in via recovery code.", 'otp_invalid_recovery_code'
    error_flash "Unable to add recovery codes.", 'otp_add_recovery_codes'
    error_flash "Unable to view recovery codes.", 'otp_view_recovery_codes'

    notice_flash "Additional authentication recovery codes have been added.", 'otp_recovery_codes_added'

    redirect(:otp_recovery){"#{prefix}/#{otp_recovery_route}"}

    view 'otp-add-recovery-codes', 'Authentication Recovery Codes', 'otp_add_recovery_codes'
    view 'otp-recovery', 'Enter Authentication Recovery Code', 'otp_recovery'
    view 'otp-recovery-codes', 'View Authentication Recovery Codes', 'otp_recovery_codes'

    auth_value_method :otp_add_recovery_codes_param, 'otp_add'
    auth_value_method :otp_invalid_recovery_code_message, "Invalid recovery code"
    auth_value_method :otp_recovery_codes_limit, 16
    auth_value_method :otp_recovery_codes_column, :code
    auth_value_method :otp_recovery_codes_id_column, :id
    auth_value_method :otp_recovery_codes_label, 'Recovery Code'
    auth_value_method :otp_recovery_codes_param, 'otp_recovery_code'
    auth_value_method :otp_recovery_codes_table, :account_otp_recovery_codes

    auth_value_methods(
      :otp_recovery_codes_route,
      :otp_recovery_route
    )

    auth_methods(
      :otp_new_recovery_code,
      :otp_add_recovery_code,
      :otp_can_add_recovery_codes?,
      :otp_recovery_code_match?,
      :otp_recovery_codes
    )

    self::ROUTE_BLOCK = proc do |r, auth|
      r.is auth.otp_recovery_route do
        auth.require_otp_not_authenticated
        auth._before_otp_recovery

        r.get do
          auth.otp_recovery_view
        end

        r.post do
          if auth.otp_recovery_code_match?(auth.param(auth.otp_recovery_codes_param))
            auth.otp_remove_auth_failures
            auth.successful_otp_authentication(:recovery_code)
          end

          @otp_recovery_error = auth.otp_invalid_recovery_code_message
          auth.set_error_flash auth.otp_invalid_recovery_code_error_flash

          auth.otp_recovery_view
        end
      end

      r.is auth.otp_recovery_codes_route do
        auth.require_account
        auth.require_otp
        auth._before_otp_recovery_codes

        r.get do
          auth.otp_recovery_codes_view
        end

        r.post do
          if auth.otp_password_match?(auth.param(auth.password_param))
            if auth.otp_can_add_recovery_codes?
              if auth._param(auth.otp_add_recovery_codes_param)
                auth.otp_add_recovery_codes(auth.otp_recovery_codes_limit - auth._otp_recovery_codes.length)
                auth.set_notice_now_flash auth.otp_recovery_codes_added_notice_flash
              end

              @otp_add_recovery_codes = auth.otp_add_recovery_codes_button
            end

            auth.otp_add_recovery_codes_view
          else
            if auth._param(auth.otp_add_recovery_codes_param)
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

    def otp_auth_form_footer
      "#{super}<p><a href=\"#{otp_recovery_route}\">Authenticate using recovery code</a></p>"
    end

    def otp_locked_out_redirect
      otp_recovery_redirect
    end

    def otp_lockout_error_flash
      "#{super} Can use recovery code to unlock."
    end

    def otp_remove
      super
      otp_recovery_codes_ds.delete
    end

    def otp_add_key(secret)
      super
      otp_add_recovery_codes(otp_recovery_codes_limit)
    end

    def otp_recovery_route
      "#{otp_base_route}/recovery"
    end

    def otp_recovery_codes_route
      "#{otp_base_route}/recovery-codes"
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
      # This should never raise uniqueness violations unless the recovery code is the same, and the odds of that
      # are 1/256**32 assuming a good random number generator.  Still, attempt to handle that case by retrying
      # on such a uniqueness violation.
      retry_on_uniqueness_violation do
        otp_recovery_codes_ds.insert(otp_recovery_codes_id_column=>session_value, otp_recovery_codes_column=>otp_new_recovery_code)
      end
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
    
    private

    def otp_recovery_codes_ds
      db[otp_recovery_codes_table].where(otp_recovery_codes_id_column=>session_value)
    end
  end
end
