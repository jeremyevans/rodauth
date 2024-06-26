# frozen-string-literal: true

module Rodauth
  Feature.define(:otp_lockout_email, :OtpLockoutEmail) do
    depends :otp_unlock, :email_base

    loaded_templates %w'otp-locked-out-email otp-unlocked-email otp-unlock-failed-email'
    email :otp_locked_out, 'TOTP Authentication Locked Out', :translatable=>true
    email :otp_unlocked, 'TOTP Authentication Unlocked', :translatable=>true
    email :otp_unlock_failed, 'TOTP Authentication Unlocking Failed', :translatable=>true

    auth_value_method :send_otp_locked_out_email?, true
    auth_value_method :send_otp_unlocked_email?, true
    auth_value_method :send_otp_unlock_failed_email?, true

    private

    def after_otp_authentication_failure
      super

      if otp_locked_out? && send_otp_locked_out_email?
        send_otp_locked_out_email
      end
    end

    def after_otp_unlock_auth_success
      super

      if !otp_locked_out? && send_otp_unlocked_email?
        send_otp_unlocked_email
      end
    end

    def after_otp_unlock_auth_failure
      super

      if send_otp_unlock_failed_email?
        send_otp_unlock_failed_email
      end
    end
  end
end
