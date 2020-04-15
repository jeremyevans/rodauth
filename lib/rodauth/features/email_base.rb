# frozen-string-literal: true

module Rodauth
  Feature.define(:email_base, :EmailBase) do
    translatable_method :email_subject_prefix, ''
    auth_value_method :require_mail?, true
    auth_value_method :allow_raw_email_token?, false

    redirect :default_post_email

    auth_value_methods(
      :email_from
    )

    auth_methods(
      :create_email,
      :email_to,
      :send_email
    )

    def post_configure
      super
      require 'mail' if require_mail?
    end

    private

    def send_email(email)
      email.deliver!
    end

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
      "webmaster@#{domain}"
    end

    def email_to
      account[login_column]
    end

    def token_link(route, param, key)
      route_url(route, param => "#{account_id}#{token_separator}#{convert_email_token_key(key)}")
    end

    def convert_email_token_key(key)
      convert_token_key(key)
    end

    def account_from_key(token, status_id=nil)
      id, key = split_token(token)
      return unless id && key

      return unless actual = yield(id)

      unless timing_safe_eql?(key, convert_email_token_key(actual))
        if hmac_secret && allow_raw_email_token?
          return unless timing_safe_eql?(key, actual)
        else
          return
        end
      end

      ds = account_ds(id)
      ds = ds.where(account_status_column=>status_id) if status_id && !skip_status_checks?
      ds.first
    end
  end
end
