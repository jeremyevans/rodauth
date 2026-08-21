# frozen-string-literal: true

module Rodauth
  Feature.define(:require_domain, :RequireDomain) do
    def post_configure
      super
      if method(:domain).owner == Rodauth::Base
        missing_recommended_configuration("The Rodauth 'domain' configuration method was not used. This can potentially leave the application vulnerable to requests that use malicious or invalid domains.")
      end
    end
  end
end
