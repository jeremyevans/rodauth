# frozen-string-literal: true

module Rodauth
  Feature.define(:reset_password_notify, :ResetPasswordNotify) do
    depends :reset_password
    loaded_templates %w'reset-password-notify-email'
    email :reset_password_notify, 'Password Reset Completed', :translatable=>true

    private

    def after_reset_password
      super
      send_reset_password_notify_email
    end
  end
end
