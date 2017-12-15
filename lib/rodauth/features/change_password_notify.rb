# frozen-string-literal: true

module Rodauth
  Feature.define(:change_password_notify, :ChangePasswordNotify) do
    depends :change_password, :email_base

    auth_value_method :password_changed_email_subject, 'Password Changed'

    auth_value_methods(
      :password_changed_email_body
    )
    auth_methods(
      :create_password_changed_email,
      :send_password_changed_email
    )

    private

    def send_password_changed_email
      create_password_changed_email.deliver!
    end

    def create_password_changed_email
      create_email(password_changed_email_subject, password_changed_email_body)
    end

    def password_changed_email_body
      render('password-changed-email')
    end

    def after_change_password
      super
      send_password_changed_email
    end
  end
end

