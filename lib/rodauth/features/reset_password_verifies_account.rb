# frozen-string-literal: true

module Rodauth
  Feature.define(:reset_password_verifies_account, :ResetPasswordVerifiesAccount) do
    depends :reset_password, :verify_account

    def reset_password_request_for_unverified_account
      nil
    end

    private

    def after_reset_password
      super

      unless open_account?
        verify_account
        remove_verify_account_key
      end
    end

    def reset_password_account_status_value
      Array(super) << account_unverified_status_value
    end
  end
end
