# frozen-string-literal: true

module Rodauth
  Feature.define(:email_auth, :EmailAuth) do
    depends :login, :email_base

    notice_flash "An email has been sent to you with a link to login to your account", 'email_auth_email_sent'
    error_flash "There was an error logging you in"
    error_flash "There was an error requesting an email link to authenticate", 'email_auth_request'
    error_flash "An email has recently been sent to you with a link to login", 'email_auth_email_recently_sent'
    error_flash "There was an error logging you in: invalid email authentication key", 'no_matching_email_auth_key'
    loaded_templates %w'email-auth email-auth-request-form email-auth-email'

    view 'email-auth', 'Login'
    additional_form_tags
    additional_form_tags 'email_auth_request'
    before 'email_auth_request'
    after 'email_auth_request'
    button 'Send Login Link Via Email', 'email_auth_request'
    redirect(:email_auth_email_sent){default_post_email_redirect}
    redirect(:email_auth_email_recently_sent){default_post_email_redirect}
    response :email_auth_email_sent
    email :email_auth, 'Login Link'
    
    auth_value_method :email_auth_deadline_column, :deadline
    auth_value_method :email_auth_deadline_interval, {:days=>1}.freeze
    auth_value_method :email_auth_id_column, :id
    auth_value_method :email_auth_key_column, :key
    auth_value_method :email_auth_key_param, 'key'
    auth_value_method :email_auth_email_last_sent_column, :email_last_sent
    auth_value_method :email_auth_skip_resend_email_within, 300
    auth_value_method :email_auth_table, :account_email_auth_keys
    auth_value_method :force_email_auth?, false
    session_key :email_auth_session_key, :email_auth_key
    
    auth_methods(
      :create_email_auth_key,
      :email_auth_email_link,
      :email_auth_key_insert_hash,
      :email_auth_key_value,
      :email_auth_request_form,
      :get_email_auth_key,
      :get_email_auth_email_last_sent,
      :remove_email_auth_key,
      :set_email_auth_email_last_sent
    )

    auth_private_methods :account_from_email_auth_key

    internal_request_method
    internal_request_method :email_auth_request
    internal_request_method :valid_email_auth?

    route(:email_auth_request) do |r|
      check_already_logged_in
      before_email_auth_request_route

      r.post do
        if account_from_login(login_param_value) && open_account?
          _email_auth_request
        end

        set_redirect_error_status(no_matching_login_error_status)
        set_error_reason :no_matching_login
        set_redirect_error_flash email_auth_request_error_flash
        redirect email_auth_email_sent_redirect
      end
    end

    route do |r|
      check_already_logged_in
      before_email_auth_route

      r.get do
        if key = param_or_nil(email_auth_key_param)
          set_session_value(email_auth_session_key, key)
          redirect(r.path)
        end

        if (key = session[email_auth_session_key]) && account_from_email_auth_key(key)
          email_auth_view
        else
          remove_session_value(email_auth_session_key)
          set_redirect_error_flash no_matching_email_auth_key_error_flash
          redirect require_login_redirect
        end
      end

      r.post do
        key = session[email_auth_session_key] || param(email_auth_key_param)
        unless account_from_email_auth_key(key)
          set_redirect_error_status(invalid_key_error_status)
          set_error_reason :invalid_email_auth_key
          set_redirect_error_flash email_auth_error_flash
          redirect email_auth_email_sent_redirect
        end

        login('email_auth')
      end
    end

    def create_email_auth_key
      transaction do
        if email_auth_key_value = get_email_auth_key(account_id)
          set_email_auth_email_last_sent
          @email_auth_key_value = email_auth_key_value
        elsif e = raised_uniqueness_violation{email_auth_ds.insert(email_auth_key_insert_hash)}
          # If inserting into the email auth table causes a violation, we can pull the 
          # existing email auth key from the table, or reraise.
          raise e unless @email_auth_key_value = get_email_auth_key(account_id)
        end
      end
    end

    def set_email_auth_email_last_sent
       email_auth_ds.update(email_auth_email_last_sent_column=>Sequel::CURRENT_TIMESTAMP) if email_auth_email_last_sent_column
    end

    def get_email_auth_email_last_sent
      if column = email_auth_email_last_sent_column
        if ts = email_auth_ds.get(column)
          convert_timestamp(ts)
        end
      end
    end

    def remove_email_auth_key
      email_auth_ds.delete
    end

    def account_from_email_auth_key(key)
      @account = _account_from_email_auth_key(key)
    end

    def email_auth_email_link
      token_link(email_auth_route, email_auth_key_param, email_auth_key_value)
    end

    def get_email_auth_key(id)
      ds = email_auth_ds(id)
      ds.where(Sequel::CURRENT_TIMESTAMP > email_auth_deadline_column).delete
      ds.get(email_auth_key_column)
    end

    def email_auth_request_form
      render('email-auth-request-form')
    end

    def after_login_entered_during_multi_phase_login
      # If forcing email auth, just send the email link.
      _email_auth_request if force_email_auth?

      super
    end

    def use_multi_phase_login?
      true
    end

    def possible_authentication_methods
      methods = super
      methods << 'email_auth' if !methods.include?('password') && allow_email_auth?
      methods
    end

    def email_auth_email_recently_sent?
      (email_last_sent = get_email_auth_email_last_sent) && (Time.now - email_last_sent < email_auth_skip_resend_email_within)
    end

    private

    def _multi_phase_login_forms
      forms = super
      forms << [30, email_auth_request_form, :_email_auth_request] if valid_login_entered? && allow_email_auth?
      forms
    end

    def _email_auth_request
      if email_auth_email_recently_sent?
        set_redirect_error_flash email_auth_email_recently_sent_error_flash
        redirect email_auth_email_recently_sent_redirect
      end

      generate_email_auth_key_value
      transaction do
        before_email_auth_request
        create_email_auth_key
        send_email_auth_email
        after_email_auth_request
      end

      email_auth_email_sent_response
    end

    attr_reader :email_auth_key_value

    def allow_email_auth?
      defined?(super) ? super : true
    end

    def after_login
      # Remove the email auth key after any login, even if
      # it is a password login.  This is done to invalidate
      # the email login when a user has a password and requests
      # email authentication, but then remembers their password
      # and doesn't need the link.  At that point, the link
      # that allows login access to the account becomes a
      # security liability, and it is best to remove it.
      remove_email_auth_key
      super
    end

    def after_close_account
      remove_email_auth_key
      super if defined?(super)
    end

    def generate_email_auth_key_value
      @email_auth_key_value = random_key
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
