# frozen-string-literal: true

module Rodauth
  Feature.define(:sms_codes, :SmsCodes) do
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

    error_flash "Error authenticating via SMS code", 'sms_invalid_code'
    error_flash "Error disabling SMS authentication", 'sms_disable'
    error_flash "Error setting up SMS authentication", 'sms_setup'
    error_flash "Invalid or out of date SMS confirmation code used, must setup SMS authentication again", 'sms_invalid_confirmation_code'
    error_flash "No current SMS code for this account", 'no_current_sms_code'
    error_flash "SMS authentication has been locked out", 'sms_lockout'
    error_flash "SMS authentication has already been setup", 'sms_already_setup'
    error_flash "SMS authentication has not been setup yet", 'sms_not_setup'
    error_flash "SMS authentication needs confirmation", 'sms_needs_confirmation'

    notice_flash "SMS authentication code has been sent", 'sms_request'
    notice_flash "SMS authentication has been disabled", 'sms_disable'
    notice_flash "SMS authentication has been setup", 'sms_confirm'

    translatable_method :sms_auth_link_text, "Authenticate Using SMS Code"
    translatable_method :sms_setup_link_text, "Setup Backup SMS Authentication"
    translatable_method :sms_disable_link_text, "Disable SMS Authentication"

    redirect :sms_already_setup
    redirect :sms_confirm
    redirect :sms_disable
    redirect(:sms_auth){sms_auth_path}
    redirect(:sms_needs_confirmation){sms_confirm_path}
    redirect(:sms_needs_setup){sms_setup_path}
    redirect(:sms_request){sms_request_path}
    redirect(:sms_lockout){two_factor_auth_required_redirect}

    response :sms_confirm
    response :sms_disable
    response :sms_needs_confirmation

    loaded_templates %w'sms-auth sms-confirm sms-disable sms-request sms-setup sms-code-field password-field'
    view 'sms-auth', 'Authenticate via SMS Code', 'sms_auth'
    view 'sms-confirm', 'Confirm SMS Backup Number', 'sms_confirm'
    view 'sms-disable', 'Disable Backup SMS Authentication', 'sms_disable'
    view 'sms-request', 'Send SMS Code', 'sms_request'
    view 'sms-setup', 'Setup SMS Backup Number', 'sms_setup'

    auth_value_method :sms_already_setup_error_status, 403
    auth_value_method :sms_needs_confirmation_error_status, 403

    auth_value_method :sms_auth_code_length, 6
    auth_value_method :sms_code_allowed_seconds, 300
    auth_value_method :sms_code_column, :code
    translatable_method :sms_code_label, 'SMS Code'
    auth_value_method :sms_code_param, 'sms-code'
    auth_value_method :sms_codes_table, :account_sms_codes
    auth_value_method :sms_confirm_code_length, 12
    auth_value_method :sms_confirm_deadline, 86400
    auth_value_method :sms_failure_limit, 5
    auth_value_method :sms_failures_column, :num_failures
    auth_value_method :sms_id_column, :id
    translatable_method :sms_invalid_code_message, "invalid SMS code"
    translatable_method :sms_invalid_phone_message, "invalid SMS phone number"
    auth_value_method :sms_issued_at_column, :code_issued_at
    auth_value_method :sms_phone_column, :phone_number
    translatable_method :sms_phone_label, 'Phone Number'
    auth_value_method :sms_phone_input_type, 'tel'
    auth_value_method :sms_phone_min_length, 7
    auth_value_method :sms_phone_param, 'sms-phone'

    auth_cached_method :sms

    auth_value_methods(
      :sms_codes_primary?,
      :sms_needs_confirmation_notice_flash,
      :sms_request_response
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
      :sms_remove_expired_confirm_code,
      :sms_remove_failures,
      :sms_send,
      :sms_set_code,
      :sms_setup,
      :sms_setup?,
      :sms_valid_phone?
    )

    internal_request_method :sms_setup
    internal_request_method :sms_confirm
    internal_request_method :sms_request
    internal_request_method :sms_auth
    internal_request_method :valid_sms_auth?
    internal_request_method :sms_disable

    route(:sms_request) do |r|
      require_login
      require_account_session
      require_two_factor_not_authenticated('sms_code')
      require_sms_available
      before_sms_request_route

      r.get do
        sms_request_view
      end

      r.post do
        transaction do
          before_sms_request
          sms_send_auth_code
          after_sms_request
        end

        require_response(:_sms_request_response)
      end
    end

    route(:sms_auth) do |r|
      require_login
      require_account_session
      require_two_factor_not_authenticated('sms_code')
      require_sms_available

      unless sms_current_auth?
        if sms_code
          sms_set_code(nil)
        end

        set_response_error_reason_status(:no_current_sms_code, invalid_key_error_status)
        set_redirect_error_flash no_current_sms_code_error_flash
        redirect sms_request_redirect
      end

      before_sms_auth_route

      r.get do
        sms_auth_view
      end

      r.post do
        transaction do
          if sms_code_match?(param(sms_code_param))
            before_sms_auth
            sms_remove_failures
            two_factor_authenticate('sms_code')
          else
            sms_record_failure
            after_sms_failure
          end
        end

        set_response_error_reason_status(:invalid_sms_code, invalid_key_error_status)
        set_field_error(sms_code_param, sms_invalid_code_message)
        set_error_flash sms_invalid_code_error_flash
        sms_auth_view
      end
    end

    route(:sms_setup) do |r|
      require_account
      unless sms_codes_primary?
        require_two_factor_setup
        require_two_factor_authenticated
      end
      sms_remove_expired_confirm_code
      require_sms_not_setup

      if sms_needs_confirmation?
        set_redirect_error_status(sms_needs_confirmation_error_status)
        set_error_reason :sms_needs_confirmation
        set_redirect_error_flash sms_needs_confirmation_error_flash
        redirect sms_needs_confirmation_redirect
      end

      before_sms_setup_route

      r.get do
        sms_setup_view
      end

      r.post do
        catch_error do
          unless two_factor_password_match?(param(password_param))
            throw_error_reason(:invalid_password, invalid_password_error_status, password_param, invalid_password_message)
          end

          phone = sms_normalize_phone(param(sms_phone_param))

          unless sms_valid_phone?(phone)
            throw_error_reason(:invalid_phone_number, invalid_field_error_status, sms_phone_param, sms_invalid_phone_message)
          end

          transaction do
            before_sms_setup
            sms_setup(phone)
            sms_send_confirm_code
            after_sms_setup
          end

          sms_needs_confirmation_response
        end

        set_error_flash sms_setup_error_flash
        sms_setup_view
      end
    end

    route(:sms_confirm) do |r|
      require_account
      unless sms_codes_primary?
        require_two_factor_setup
        require_two_factor_authenticated
      end
      sms_remove_expired_confirm_code
      require_sms_not_setup
      before_sms_confirm_route

      r.get do
        sms_confirm_view
      end

      r.post do
        if sms_confirmation_match?(param(sms_code_param))
          transaction do
            before_sms_confirm
            sms_confirm
            after_sms_confirm
            unless two_factor_authenticated?
              two_factor_update_session('sms_code')
            end
          end

          sms_confirm_response
        end

        sms_confirm_failure
        set_redirect_error_status(invalid_key_error_status)
        set_error_reason :invalid_sms_confirmation_code
        set_redirect_error_flash sms_invalid_confirmation_code_error_flash
        redirect sms_needs_setup_redirect
      end
    end

    route(:sms_disable) do |r|
      require_account
      require_sms_setup
      before_sms_disable_route

      r.get do
        sms_disable_view
      end

      r.post do
        if two_factor_password_match?(param(password_param))
          transaction do
            before_sms_disable
            sms_disable
            if two_factor_login_type_match?('sms_code')
              two_factor_remove_session('sms_code')
            end
            after_sms_disable
          end
          sms_disable_response
        end

        set_response_error_reason_status(:invalid_password, invalid_password_error_status)
        set_field_error(password_param, invalid_password_message)
        set_error_flash sms_disable_error_flash
        sms_disable_view
      end
    end

    def two_factor_remove
      super
      sms_disable
    end

    def two_factor_remove_auth_failures
      super
      sms_remove_failures
    end

    def require_sms_setup
      unless sms_setup?
        set_redirect_error_status(two_factor_not_setup_error_status)
        set_error_reason :sms_not_setup
        set_redirect_error_flash sms_not_setup_error_flash
        redirect sms_needs_setup_redirect
      end
    end

    def require_sms_not_setup
      if sms_setup?
        set_redirect_error_status(sms_already_setup_error_status)
        set_error_reason :sms_already_setup
        set_redirect_error_flash sms_already_setup_error_flash
        redirect sms_already_setup_redirect
      end
    end

    def require_sms_available
      require_sms_setup

      if sms_locked_out?
        set_redirect_error_status(lockout_error_status)
        set_error_reason :sms_locked_out
        set_redirect_error_flash sms_lockout_error_flash
        redirect sms_lockout_redirect
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
      @sms = nil
    end

    def sms_confirm_failure
      sms_ds.delete
    end

    def sms_setup(phone_number)
      # Cannot handle uniqueness violation here, as the phone number given may not match the
      # one in the table.
      sms_ds.insert(sms_id_column=>session_value, sms_phone_column=>phone_number, sms_failures_column => nil)
      remove_instance_variable(:@sms) if instance_variable_defined?(:@sms)
    end

    def sms_remove_failures
      return if sms_needs_confirmation?
      update_hash_ds(sms, sms_ds.exclude(sms_failures_column => nil), sms_failures_column => 0, sms_code_column => nil)
    end

    def sms_confirm
      update_hash_ds(sms, sms_ds.where(sms_failures_column => nil), sms_failures_column => 0, sms_code_column => nil)
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

    def sms_valid_phone?(phone)
      phone.length >= sms_phone_min_length
    end

    def sms_auth_message(code)
      "SMS authentication code for #{domain} is #{code}"
    end

    def sms_confirm_message(code)
      "SMS confirmation code for #{domain} is #{code}"
    end

    def sms_needs_confirmation_notice_flash
      sms_needs_confirmation_error_flash
    end

    def sms_set_code(code)
     update_sms(sms_code_column=>code, sms_issued_at_column=>Sequel::CURRENT_TIMESTAMP)
    end

    def sms_remove_expired_confirm_code
      db[sms_codes_table].
        where(sms_id_column=>session_value, sms_failures_column => nil).
        where(Sequel[sms_issued_at_column] < Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: sms_confirm_deadline)).
        delete
    end

    def sms_record_failure
      update_sms(sms_failures_column=>Sequel.expr(sms_failures_column)+1)
      sms[sms_failures_column] = sms_ds.get(sms_failures_column)
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
      sms_setup? && !sms_locked_out?
    end

    def sms_locked_out?
      sms_failures >= sms_failure_limit
    end

    def sms_current_auth?
      sms_code && sms_code_issued_at + sms_code_allowed_seconds > Time.now
    end

    def possible_authentication_methods
      methods = super
      methods << 'sms_code' if sms_setup?
      methods
    end

    private

    def _sms_request_response
      set_notice_flash sms_request_notice_flash
      redirect sms_auth_redirect
    end

    def _two_factor_auth_links
      links = super
      links << [30, sms_request_path, sms_auth_link_text] if sms_available?
      links
    end

    def _two_factor_setup_links
      links = super
      links << [30, sms_setup_path, sms_setup_link_text] if !sms_setup? && (sms_codes_primary? || uses_two_factor_authentication?)
      links
    end

    def _two_factor_remove_links
      links = super
      links << [30, sms_disable_path, sms_disable_link_text] if sms_setup?
      links
    end

    def _two_factor_remove_all_from_session
      two_factor_remove_session('sms_code')
      super
    end

    def sms_codes_primary?
      (features & [:otp, :webauthn]).empty?
    end

    def sms_normalize_phone(phone)
      phone.to_s.gsub(/\D+/, '')
    end

    def sms_new_auth_code
      SecureRandom.random_number(10**sms_auth_code_length).to_s.rjust(sms_auth_code_length, "0")
    end

    def sms_new_confirm_code
      SecureRandom.random_number(10**sms_confirm_code_length).to_s.rjust(sms_confirm_code_length, "0")
    end

    def sms_send(phone, message)
      raise ConfigurationError, "sms_send needs to be defined in the Rodauth configuration for SMS sending to work"
    end

    def update_sms(values)
      update_hash_ds(sms, sms_ds, values)
    end

    def _sms
      sms_ds.first
    end

    def sms_ds
      db[sms_codes_table].where(sms_id_column=>session_value)
    end

    def use_date_arithmetic?
      true
    end
  end
end
