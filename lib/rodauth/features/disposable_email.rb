# frozen-string-literal: true

module Rodauth
  Feature.define(:disposable_email, :DisposableEmail) do
    auth_value_method :disposable_email_providers_file, File.expand_path('../../../../dict/dispoable_email_provider.txt', __FILE__)
    translatable_method :email_use_a_disposable_provider_message, "is a disposable email"
    auth_value_method :disposable_email_providers, nil

    auth_methods :disposable_email?

    def post_configure
      super

      return if disposable_email_providers || !disposable_email_providers_file

      require 'set'

      disposable_email_providers = Set.new(File.read(disposable_email_providers_file).split("\n").each(&:freeze)).freeze
      self.class.send(:define_method, :disposable_email_providers) { disposable_email_providers }
    end

    def disposable_email?(email)
      email_provider = email.split('@').last
      disposable_email_providers.include?(email_provider)
    end

    def login_meets_email_requirements?(email)
      other_requirement_met = super

      return other_requirement_met unless other_requirement_met
      return true unless disposable_email?(email)

      @login_requirement_message = email_use_a_disposable_provider_message
      false
    end
  end
end
