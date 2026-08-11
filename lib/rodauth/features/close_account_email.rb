# frozen-string-literal: true

module Rodauth
  Feature.define(:close_account_email, :CloseAccountEmail) do
    depends :close_account, :email_base

    loaded_templates %w'close-account-email'
    email :close_account, 'Account Closed', :translatable=>true

    private

    def after_close_account
      super
      send_close_account_email
    end
  end
end
