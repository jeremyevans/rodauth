# frozen-string-literal: true

module Rodauth
  Feature.define(:verify_change_login, :VerifyChangeLogin) do
    depends :change_login, :verify_account_grace_period

    def change_login_notice_flash
      "#{super}. #{verify_account_email_sent_notice_flash}"
    end

    private

    def after_change_login
      super
      update_account(account_status_column=>account_unverified_status_value)
      setup_account_verification
      session[unverified_account_session_key] = true
    end
  end
end
