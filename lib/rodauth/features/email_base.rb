module Rodauth
  EmailBase = Feature.define(:email_base) do
    auth_value_method :email_subject_prefix, nil
    auth_value_method :require_mail?, true

    auth_value_methods(
      :email_from
    )

    auth_methods(
      :create_email,
      :email_to
    )

    def email_from
      "webmaster@#{request.host}"
    end

    def email_to
      account[login_column]
    end

    def create_email(subject, body)
      m = Mail.new
      m.from = email_from
      m.to = email_to
      m.subject = "#{email_subject_prefix}#{subject}"
      m.body = body
      m
    end

    def post_configure
      super
      require 'mail' if require_mail?
    end
  end
end
