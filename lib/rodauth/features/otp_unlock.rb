# frozen-string-literal: true

module Rodauth
  Feature.define(:otp_unlock, :OtpUnlock) do
    depends :otp

    before 'otp_unlock_attempt'
    after 'otp_unlock_auth_success'
    after 'otp_unlock_auth_failure'
    after 'otp_unlock_not_yet_available'

    error_flash "TOTP authentication is not currently locked out", 'otp_unlock_not_locked_out'
    error_flash "TOTP invalid authentication", 'otp_unlock_auth_failure'
    error_flash "Deadline past for unlocking TOTP authentication", 'otp_unlock_auth_deadline_passed'
    error_flash "TOTP unlock attempt not yet available", 'otp_unlock_auth_not_yet_available'

    notice_flash "TOTP authentication unlocked", 'otp_unlocked'
    notice_flash "TOTP successful authentication, more successful authentication needed to unlock", 'otp_unlock_auth_success'

    redirect :otp_unlock_not_locked_out
    redirect :otp_unlocked

    additional_form_tags

    button 'Authenticate Using TOTP to Unlock', 'otp_unlock'

    auth_value_method :otp_unlock_auth_deadline_passed_error_status, 403
    auth_value_method :otp_unlock_auth_failure_cooldown_seconds, 900
    auth_value_method :otp_unlock_auth_failure_error_status, 403
    auth_value_method :otp_unlock_auth_not_yet_available_error_status, 403
    auth_value_method :otp_unlock_auths_required, 3
    auth_value_method :otp_unlock_deadline_seconds, 900
    auth_value_method :otp_unlock_id_column, :id
    auth_value_method :otp_unlock_next_auth_attempt_after_column, :next_auth_attempt_after
    auth_value_method :otp_unlock_not_locked_out_error_status, 403
    auth_value_method :otp_unlock_num_successes_column, :num_successes
    auth_value_method :otp_unlock_table, :account_otp_unlocks

    translatable_method :otp_unlock_consecutive_successes_label, 'Consecutive successful authentications'
    translatable_method :otp_unlock_form_footer, ''
    translatable_method :otp_unlock_next_auth_attempt_label, 'Can attempt next authentication after'
    translatable_method :otp_unlock_next_auth_attempt_refresh_label, 'Page will automatically refresh when authentication is possible.'
    translatable_method :otp_unlock_next_auth_deadline_label, 'Deadline for next authentication'
    translatable_method :otp_unlock_required_consecutive_successes_label, 'Required consecutive successful authentications to unlock'

    loaded_templates %w'otp-unlock otp-unlock-not-available'
    view 'otp-unlock', 'Unlock TOTP Authentication', 'otp_unlock'
    view 'otp-unlock-not-available', 'Must Wait to Unlock TOTP Authentication', 'otp_unlock_not_available'

    auth_methods(
      :otp_unlock_auth_failure,
      :otp_unlock_auth_success,
      :otp_unlock_available?,
      :otp_unlock_deadline_passed?,
      :otp_unlock_refresh_tag,
    )

    route(:otp_unlock) do |r|
      require_login
      require_account_session
      require_otp_setup

      unless otp_locked_out?
        set_response_error_reason_status(:otp_not_locked_out, otp_unlock_not_locked_out_error_status)
        set_redirect_error_flash otp_unlock_not_locked_out_error_flash
        redirect otp_unlock_not_locked_out_redirect
      end

      before_otp_unlock_route

      r.get do
        if otp_unlock_available?
          otp_unlock_view
        else
          otp_unlock_not_available_view
        end
      end

      r.post do
        db.transaction do
          if otp_unlock_deadline_passed?
            set_response_error_reason_status(:otp_unlock_deadline_passed, otp_unlock_auth_deadline_passed_error_status)
            set_redirect_error_flash otp_unlock_auth_deadline_passed_error_flash
          elsif !otp_unlock_available?
            after_otp_unlock_not_yet_available
            set_response_error_reason_status(:otp_unlock_not_yet_available, otp_unlock_auth_not_yet_available_error_status)
            set_redirect_error_flash otp_unlock_auth_not_yet_available_error_flash
          else
            before_otp_unlock_attempt
            if otp_valid_code?(param(otp_auth_param))
              otp_unlock_auth_success
              after_otp_unlock_auth_success

              unless otp_locked_out?
                set_notice_flash otp_unlocked_notice_flash
                redirect otp_unlocked_redirect
              end

              set_notice_flash otp_unlock_auth_success_notice_flash
            else
              otp_unlock_auth_failure
              after_otp_unlock_auth_failure
              set_response_error_reason_status(:otp_unlock_auth_failure, otp_unlock_auth_failure_error_status)
              set_redirect_error_flash otp_unlock_auth_failure_error_flash
            end
          end
        end

        redirect request.path
      end
    end

    def otp_unlock_available?
      if otp_unlock_data
        next_auth_attempt_after = otp_unlock_next_auth_attempt_after
        current_timestamp = Time.now

        if (next_auth_attempt_after < current_timestamp - otp_unlock_deadline_seconds)
          # Unlock process not fully completed within deadline, reset process
          otp_unlock_reset
          true
        else
          if next_auth_attempt_after > current_timestamp
            # If next auth attempt after timestamp is in the future, that means the next
            # unlock attempt cannot happen until then.
            false 
          else
            if otp_unlock_num_successes == 0
              # 0 value indicates previous attempt was a failure. Since failure cooldown
              # period has passed, reset process so user gets full deadline period
              otp_unlock_reset
            end
            true
          end
        end
      else
        # No row means no unlock attempts yet (or previous attempt was more than the
        # deadline account, so unlocking is available
        true
      end
    end

    def otp_unlock_auth_failure
      h = {
        otp_unlock_num_successes_column=>0,
        otp_unlock_next_auth_attempt_after_column=>Sequel.date_add(Sequel::CURRENT_TIMESTAMP, :seconds=>otp_unlock_auth_failure_cooldown_seconds)
      }

      if otp_unlock_ds.update(h) == 0
        h[otp_unlock_id_column] = session_value

        # If row already exists when inserting, no need to do anything
        raises_uniqueness_violation?{otp_unlock_ds.insert(h)}
      end
    end

    def otp_unlock_auth_success
      deadline = Sequel.date_add(Sequel::CURRENT_TIMESTAMP, :seconds=>otp_unlock_success_cooldown_seconds)

      # Add WHERE to avoid possible race condition when multiple unlock auth requests
      # are sent at the same time (only the first should increment num successes).
      if otp_unlock_ds.
          where(Sequel[otp_unlock_next_auth_attempt_after_column] < Sequel::CURRENT_TIMESTAMP).
          update(
            otp_unlock_num_successes_column=>Sequel[otp_unlock_num_successes_column]+1,
            otp_unlock_next_auth_attempt_after_column=>deadline
          ) == 0

        # Ignore uniqueness errors when inserting after a failed update, 
        # which could be caused due to the race condition mentioned above.
        raises_uniqueness_violation? do
          otp_unlock_ds.insert(
            otp_unlock_id_column=>session_value,
            otp_unlock_next_auth_attempt_after_column=>deadline
          )
        end
      end

      @otp_unlock_data = nil
      # :nocov:
      if otp_unlock_data
      # :nocov:
        if otp_unlock_num_successes >= otp_unlock_auths_required
          # At least the requisite number of consecutive successful unlock
          # authentications. Unlock OTP authentication.
          otp_key_ds.update(otp_keys_failures_column => 0)

          # Remove OTP unlock metadata when unlocking OTP authentication
          otp_unlock_reset
        # else
        #  # Still need additional consecutive successful unlock attempts.
        end
      # else
      #  # if row isn't available, probably the process was reset during this,
      #  # and it's safe to do nothing in that case.
      end
    end

    def otp_unlock_deadline_passed?
      otp_unlock_data ? (otp_unlock_next_auth_attempt_after < Time.now - otp_unlock_deadline_seconds) : false
    end

    def otp_unlock_refresh_tag
      "<meta http-equiv=\"refresh\" content=\"#{(otp_unlock_next_auth_attempt_after - Time.now).to_i + 1}\">"
    end

    def otp_lockout_redirect
      otp_unlock_path
    end

    def otp_unlock_next_auth_attempt_after
      if otp_unlock_data
        convert_timestamp(otp_unlock_data[otp_unlock_next_auth_attempt_after_column])
      else
        Time.now
      end
    end

    def otp_unlock_deadline
      otp_unlock_next_auth_attempt_after + otp_unlock_deadline_seconds
    end

    def otp_unlock_num_successes
      otp_unlock_data ? otp_unlock_data[otp_unlock_num_successes_column] : 0
    end

    private

    def show_otp_auth_link?
      super || (otp_exists? && otp_locked_out?)
    end

    def otp_unlock_data
      @otp_unlock_data ||= otp_unlock_ds.first
    end

    def otp_unlock_success_cooldown_seconds
      (_otp_interval+(otp_drift||0))*2
    end

    def otp_unlock_reset
      otp_unlock_ds.delete
      @otp_unlock_data = nil
    end

    def otp_unlock_ds
      db[otp_unlock_table].where(otp_unlock_id_column=>session_value)
    end
  end
end
