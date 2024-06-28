# frozen-string-literal: true

module Rodauth
  Feature.define(:otp_modify_email, :OtpModifyEmail) do
    depends :otp, :email_base

    loaded_templates %w'otp-setup-email otp-disabled-email'
    email :otp_setup, 'TOTP Authentication Setup', :translatable=>true
    email :otp_disabled, 'TOTP Authentication Disabled', :translatable=>true

    private

    def after_otp_setup
      super
      send_otp_setup_email
    end

    def after_otp_disable
      super
      send_otp_disabled_email
    end
  end
end
