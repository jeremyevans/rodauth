# frozen-string-literal: true

module Rodauth
  Feature.define(:require_hmac_secret, :RequireHmacSecret) do
    def post_configure
      super
      if method(:hmac_secret).owner == Rodauth::Base
        missing_recommended_configuration("The Rodauth 'hmac_secret' configuration method was not used. This significantly reduces Rodauth's security. Consult the Rodauth README for what this method does, and set an appropriate value.")
      end
    end
  end
end
