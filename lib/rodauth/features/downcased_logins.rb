# frozen-string-literal: true

module Rodauth
  Feature.define(:downcased_logins, :DowncasedLogins) do
    def normalize_login(login)
      login.downcase
    end
  end
end
