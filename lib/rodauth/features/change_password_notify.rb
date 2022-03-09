# frozen-string-literal: true

module Rodauth
  Feature.define(:change_password_notify, :ChangePasswordNotify) do
    depends :change_password, :email_base
    loaded_templates %w'password-changed-email'
    email :password_changed, 'Password Changed', :translatable=>true

    private

    def after_change_password
      super
      send_password_changed_email
    end
  end
end

