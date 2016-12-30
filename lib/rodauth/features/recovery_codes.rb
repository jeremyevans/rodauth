# frozen-string-literal: true

module Rodauth
  RecoveryCodes = Feature.define(:recovery_codes) do
    depends :two_factor_base

    additional_form_tags 'recovery_auth'
    additional_form_tags 'recovery_codes'

    before 'add_recovery_codes'
    before 'view_recovery_codes'
    before 'recovery_auth'
    before 'recovery_auth_route'
    before 'recovery_codes_route'

    after 'add_recovery_codes'

    button 'Add Authentication Recovery Codes', 'add_recovery_codes'
    button 'Authenticate via Recovery Code', 'recovery_auth'
    button 'View Authentication Recovery Codes', 'view_recovery_codes'

    error_flash "Error authenticating via recovery code.", 'invalid_recovery_code'
    error_flash "Unable to add recovery codes.", 'add_recovery_codes'
    error_flash "Unable to view recovery codes.", 'view_recovery_codes'

    notice_flash "Additional authentication recovery codes have been added.", 'recovery_codes_added'

    redirect(:recovery_auth){"#{prefix}/#{recovery_auth_route}"}
    redirect(:add_recovery_codes){"#{prefix}/#{recovery_codes_route}"}

    view 'add-recovery-codes', 'Authentication Recovery Codes', 'add_recovery_codes'
    view 'recovery-auth', 'Enter Authentication Recovery Code', 'recovery_auth'
    view 'recovery-codes', 'View Authentication Recovery Codes', 'recovery_codes'

    auth_value_method :add_recovery_codes_param, 'add'
    auth_value_method :invalid_recovery_code_message, "Invalid recovery code"
    auth_value_method :recovery_codes_limit, 16
    auth_value_method :recovery_codes_column, :code
    auth_value_method :recovery_codes_id_column, :id
    auth_value_method :recovery_codes_label, 'Recovery Code'
    auth_value_method :recovery_codes_param, 'recovery-code'
    auth_value_method :recovery_codes_table, :account_recovery_codes

    auth_cached_method :recovery_codes

    auth_value_methods(
      :recovery_codes_primary?
    )

    auth_methods(
      :add_recovery_code,
      :can_add_recovery_codes?,
      :new_recovery_code,
      :recovery_code_match?,
      :recovery_codes
    )

    route(:recovery_auth) do |r|
      require_login
      require_account_session
      require_two_factor_setup
      require_two_factor_not_authenticated
      before_recovery_auth_route

      r.get do
        recovery_auth_view
      end

      r.post do
        if recovery_code_match?(param(recovery_codes_param))
          before_recovery_auth
          two_factor_authenticate(:recovery_code)
        end

        set_response_error_status(invalid_key_error_status)
        set_field_error(recovery_codes_param, invalid_recovery_code_message)
        set_error_flash invalid_recovery_code_error_flash
        recovery_auth_view
      end
    end

    route(:recovery_codes) do |r|
      require_account
      unless recovery_codes_primary?
        require_two_factor_setup
        require_two_factor_authenticated
      end
      before_recovery_codes_route

      r.get do
        recovery_codes_view
      end

      r.post do
        if two_factor_password_match?(param(password_param))
          if can_add_recovery_codes?
            if param_or_nil(add_recovery_codes_param)
              transaction do
                before_add_recovery_codes
                add_recovery_codes(recovery_codes_limit - recovery_codes.length)
                after_add_recovery_codes
              end
              set_notice_now_flash recovery_codes_added_notice_flash
            end

            self.recovery_codes_button = add_recovery_codes_button
          end

          before_view_recovery_codes
          add_recovery_codes_view
        else
          if param_or_nil(add_recovery_codes_param)
            set_error_flash add_recovery_codes_error_flash
          else
            set_error_flash view_recovery_codes_error_flash
          end

          set_response_error_status(invalid_password_error_status)
          set_field_error(password_param, invalid_password_message)
          recovery_codes_view
        end
      end
    end

    attr_accessor :recovery_codes_button

    def two_factor_need_setup_redirect
      super || (add_recovery_codes_redirect if recovery_codes_primary?)
    end

    def two_factor_auth_required_redirect
      super || (recovery_auth_redirect if recovery_codes_primary?)
    end

    def two_factor_auth_fallback_redirect
      recovery_auth_redirect
    end

    def two_factor_remove
      super
      recovery_codes_remove
    end

    def two_factor_authentication_setup?
      super || (recovery_codes_primary? && !recovery_codes.empty?)
    end

    def otp_auth_form_footer
      "#{super if defined?(super)}<p><a href=\"#{recovery_auth_route}\">Authenticate using recovery code</a></p>"
    end

    def otp_lockout_redirect
      recovery_auth_redirect
    end

    def otp_lockout_error_flash
      "#{super if defined?(super)} Can use recovery code to unlock."
    end

    def otp_add_key
      super if defined?(super)
      add_recovery_codes(recovery_codes_limit - recovery_codes.length)
    end

    def sms_confirm
      super if defined?(super)
      add_recovery_codes(recovery_codes_limit - recovery_codes.length)
    end

    def otp_remove
      super if defined?(super)
      unless recovery_codes_primary?
        recovery_codes_remove
      end
    end

    def sms_disable
      super if defined?(super)
      unless recovery_codes_primary?
        recovery_codes_remove
      end
    end

    def recovery_codes_remove
      recovery_codes_ds.delete
    end

    def recovery_code_match?(code)
      recovery_codes.each do |s|
        if timing_safe_eql?(code, s)
          recovery_codes_ds.where(recovery_codes_column=>code).delete
          if recovery_codes_primary?
            add_recovery_code
          end
          return true
        end
      end
      false
    end

    def can_add_recovery_codes?
      recovery_codes.length < recovery_codes_limit
    end

    def add_recovery_codes(number)
      return if number <= 0
      transaction do
        number.times do
          add_recovery_code
        end
      end
      remove_instance_variable(:@recovery_codes)
    end

    def add_recovery_code
      # This should never raise uniqueness violations unless the recovery code is the same, and the odds of that
      # are 1/256**32 assuming a good random number generator.  Still, attempt to handle that case by retrying
      # on such a uniqueness violation.
      retry_on_uniqueness_violation do
        recovery_codes_ds.insert(recovery_codes_id_column=>session_value, recovery_codes_column=>new_recovery_code)
      end
    end

    private

    def new_recovery_code
      random_key
    end
    
    def recovery_codes_primary?
      (features & [:otp, :sms_codes]).empty?
    end

    def _recovery_codes
      recovery_codes_ds.select_map(recovery_codes_column)
    end

    def recovery_codes_ds
      db[recovery_codes_table].where(recovery_codes_id_column=>session_value)
    end
  end
end
