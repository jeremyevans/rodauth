# frozen-string-literal: true

module Rodauth
  EmailBase = Feature.define(:email_base) do
    auth_value_method :email_subject_prefix, nil
    auth_value_method :require_mail?, true
    auth_value_method :token_separator, "_"

    auth_value_methods(
      :email_from
    )

    auth_methods(
      :create_email,
      :email_to
    )

    def post_configure
      super
      require 'mail' if require_mail?
    end

    private

    def create_email(subject, body)
      create_email_to(email_to, subject, body)
    end

    def create_email_to(to, subject, body)
      m = Mail.new
      m.from = email_from
      m.to = to
      m.subject = "#{email_subject_prefix}#{subject}"
      m.body = body
      m
    end

    def email_from
      "webmaster@#{request.host}"
    end

    def email_to
      account[login_column]
    end

    def split_token(token)
      token.split(token_separator, 2)
    end

    def token_link(route, param, key)
      "#{request.base_url}#{prefix}/#{route}?#{param}=#{account_id}#{token_separator}#{key}"
    end

    def account_from_key(token, status_id=nil)
      id, key = split_token(token)
      return unless id && key

      return unless actual = yield(id)

      return unless timing_safe_eql?(key, actual)

      ds = account_ds(id)
      ds = ds.where(account_status_column=>status_id) if status_id && !skip_status_checks?
      ds.first
    end
  end
end
