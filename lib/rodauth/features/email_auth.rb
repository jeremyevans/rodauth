# frozen-string-literal: true

module Rodauth
  Feature.define(:email_auth, :EmailAuth) do
    depends :login, :email_base

    notice_flash "An email has been sent to you with a link to login to your account", 'email_auth_email_sent'
    error_flash "There was an error logging you in"
    error_flash "There was an error requesting an email link to authenticate", 'email_auth_request'
    loaded_templates %w'email-auth email-auth-request-form email-auth-email'

    view 'email-auth', 'Login'
    additional_form_tags
    additional_form_tags 'email_auth_request'
    before 'email_auth_request'
    after 'email_auth_request'
    button 'Send Login Link Via Email', 'email_auth_request'
    redirect :email_auth_email_sent
    
    auth_value_method :email_auth_deadline_column, :deadline
    auth_value_method :email_auth_deadline_interval, {:days=>1}
    auth_value_method :email_auth_email_subject, 'Login Link'
    auth_value_method :email_auth_id_column, :id
    auth_value_method :email_auth_key_column, :key
    auth_value_method :email_auth_key_param, 'key'
    auth_value_method :email_auth_table, :account_email_auth_keys
    auth_value_method :no_matching_email_auth_key_message, "invalid email authentication key"
    session_key :email_auth_session_key, :email_auth_key

    auth_value_methods :force_email_auth?
    
    auth_methods(
      :create_email_auth_email,
      :create_email_auth_key,
      :email_auth_email_body,
      :email_auth_email_link,
      :email_auth_key_insert_hash,
      :email_auth_key_value,
      :email_auth_request_form,
      :get_email_auth_key,
      :remove_email_auth_key,
      :send_email_auth_email
    )

    auth_private_methods :account_from_email_auth_key

    route(:email_auth_request) do |r|
      check_already_logged_in
      before_email_auth_request_route

      r.post do
        if account_from_login(param(login_param)) && open_account?
          _email_auth_request
        else
          set_redirect_error_status(no_matching_login_error_status)
          set_redirect_error_flash email_auth_request_error_flash
        end

        redirect email_auth_email_sent_redirect
      end
    end

    route do |r|
      check_already_logged_in
      before_email_auth_route

      r.get do
        if key = param_or_nil(email_auth_key_param)
          session[email_auth_session_key] = key
          redirect(r.path)
        end

        if key = session[email_auth_session_key]
          if account_from_email_auth_key(key)
            email_auth_view
          else
            session[email_auth_session_key] = nil
            set_redirect_error_flash no_matching_email_auth_key_message
            redirect require_login_redirect
          end
        end
      end

      r.post do
        key = session[email_auth_session_key] || param(email_auth_key_param)
        unless account_from_email_auth_key(key)
          set_redirect_error_status(invalid_key_error_status)
          set_redirect_error_flash email_auth_error_flash
          redirect email_auth_email_sent_redirect
        end

        _login
      end
    end

    def create_email_auth_key
      transaction do
        if email_auth_key_value = get_email_auth_key(account_id)
          @email_auth_key_value = email_auth_key_value
        elsif e = raised_uniqueness_violation{email_auth_ds.insert(email_auth_key_insert_hash)}
          # If inserting into the email auth table causes a violation, we can pull the 
          # existing email auth key from the table, or reraise.
          raise e unless @email_auth_key_value = get_email_auth_key(account_id)
        end
      end
    end

    def remove_email_auth_key
      email_auth_ds.delete
    end

    def account_from_email_auth_key(key)
      @account = _account_from_email_auth_key(key)
    end

    def send_email_auth_email
      create_email_auth_email.deliver!
    end

    def email_auth_email_link
      token_link(email_auth_route, email_auth_key_param, email_auth_key_value)
    end

    def get_email_auth_key(id)
      ds = email_auth_ds(id)
      ds.where(Sequel::CURRENT_TIMESTAMP > email_auth_deadline_column).delete
      ds.get(email_auth_key_column)
    end

    def login_form_footer
      footer = super
      footer += @email_auth_request_form if @email_auth_request_form
      footer
    end

    def email_auth_request_form
      render('email-auth-request-form')
    end

    def after_login_entered_during_multi_phase_login
      if force_email_auth?
        # If the account does not have a password hash, just send the
        # email link.
        _email_auth_request
        redirect email_auth_email_sent_redirect
      else
        # If the account has a password hash, allow password login, but
        # show form below to also login via email link.
        super
        @email_auth_request_form = email_auth_request_form
      end
    end

    def use_multi_phase_login?
      true
    end

    def force_email_auth?
      get_password_hash.nil?
    end

    private

    def _email_auth_request
      generate_email_auth_key_value
      transaction do
        before_email_auth_request
        create_email_auth_key
        send_email_auth_email
        after_email_auth_request
      end

      set_notice_flash email_auth_email_sent_notice_flash
    end

    attr_reader :email_auth_key_value

    def after_login
      # Remove the email auth key after any login, even if
      # it is a password login.  This is done to invalidate
      # the email login when a user has a password and requests
      # email authentication, but then remembers their password
      # and doesn't need the link.  At that point, the link
      # that allows login access to the account becomes a
      # security liability, and it is best to remove it.
      remove_email_auth_key
      super if defined?(super)
    end

    def after_close_account
      remove_email_auth_key
      super if defined?(super)
    end

    def generate_email_auth_key_value
      @email_auth_key_value = random_key
    end

    def create_email_auth_email
      create_email(email_auth_email_subject, email_auth_email_body)
    end

    def email_auth_email_body
      render('email-auth-email')
    end

    def use_date_arithmetic?
      super || db.database_type == :mysql
    end

    def email_auth_key_insert_hash
      hash = {email_auth_id_column=>account_id, email_auth_key_column=>email_auth_key_value}
      set_deadline_value(hash, email_auth_deadline_column, email_auth_deadline_interval)
      hash
    end

    def email_auth_ds(id=account_id)
      db[email_auth_table].where(email_auth_id_column=>id)
    end

    def _account_from_email_auth_key(token)
      account_from_key(token, account_open_status_value){|id| get_email_auth_key(id)}
    end
  end
end
