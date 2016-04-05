module Rodauth
  VerifyAccount = Feature.define(:verify_account) do
    depends :login, :create_account, :email_base

    route 'verify-account'
    notice_flash "Your account has been verified"
    notice_flash "An email has been sent to you with a link to verify your account", 'verify_account_email_sent'
    view 'verify-account', 'Verify Account'
    view 'verify-account-resend', 'Resend Verification Email', 'resend_verify_account'
    additional_form_tags
    additional_form_tags 'verify_account_resend'
    after
    button 'Verify Account'
    button 'Send Verification Email Again', 'verify_account_resend'
    redirect
    redirect(:verify_account_email_sent){require_login_redirect}

    auth_value_method :no_matching_verify_account_key_message, "invalid verify account key"
    auth_value_method :attempt_to_create_unverified_account_notice_message, "The account you tried to create is currently awaiting verification"
    auth_value_method :attempt_to_login_to_unverified_account_notice_message, "The account you tried to login with is currently awaiting verification"
    auth_value_method :verify_account_email_subject, 'Verify Account'
    auth_value_method :verify_account_key_param, 'key'
    auth_value_method :verify_account_autologin?, false
    auth_value_method :verify_account_table, :account_verification_keys
    auth_value_method :verify_account_id_column, :id
    auth_value_method :verify_account_key_column, :key

    auth_value_methods :verify_account_key_value

    auth_methods(
      :create_verify_account_key,
      :create_verify_account_email,
      :get_verify_account_key,
      :remove_verify_account_key,
      :resend_verify_account_view,
      :send_verify_account_email,
      :verify_account,
      :verify_account_email_body,
      :verify_account_email_link,
      :verify_account_key_insert_hash
    )

    auth_private_methods(
      :account_from_verify_account_key
    )

    get_block do |r, auth|
      if key = auth._param(auth.verify_account_key_param)
        if auth.account_from_verify_account_key(key)
          auth.verify_account_view
        else
          auth.set_redirect_error_flash auth.no_matching_verify_account_key_message
          r.redirect auth.require_login_redirect
        end
      end
    end

    post_block do |r, auth|
      if login = auth._param(auth.login_param)
        if auth.account_from_login(login) && !auth.open_account? && auth.verify_account_email_resend
          auth.set_notice_flash auth.verify_account_email_sent_notice_flash
          r.redirect auth.verify_account_email_sent_redirect
        end
      elsif key = auth._param(auth.verify_account_key_param)
        if auth.account_from_verify_account_key(key)
          auth.transaction do
            auth.verify_account
            auth.remove_verify_account_key
            auth.after_verify_account
          end
          if auth.verify_account_autologin?
            auth.update_session
          end
          auth.set_notice_flash auth.verify_account_notice_flash
          r.redirect(auth.verify_account_redirect)
        end
      end
    end

    def before_login_attempt
      unless open_account?
        set_error_flash attempt_to_login_to_unverified_account_notice_message
        response.write resend_verify_account_view
        request.halt
      end
      super
    end

    def after_create_account
      generate_verify_account_key_value
      create_verify_account_key
      send_verify_account_email
      super
    end

    def remove_verify_account_key
      verify_account_ds.delete
    end

    def verify_account
      account_ds.update(account_status_column=>account_open_status_value) == 1
    end

    def verify_account_email_resend
      if @verify_account_key_value = get_verify_account_key(account_id)
        send_verify_account_email
        true
      end
    end

    def create_account_notice_flash
      verify_account_email_sent_notice_flash
    end

    def new_account(login)
      if account_from_login(login)
        set_error_flash attempt_to_create_unverified_account_notice_message
        response.write resend_verify_account_view
        request.halt
      end
      super
    end

    def account_from_verify_account_key(key)
      @account = _account_from_verify_account_key(key)
    end

    def account_initial_status_value
      account_unverified_status_value
    end

    attr_reader :verify_account_key_value

    def send_verify_account_email
      create_verify_account_email.deliver!
    end

    def verify_account_email_link
      token_link(verify_account_route, verify_account_key_param, verify_account_key_value)
    end

    def get_verify_account_key(id)
      verify_account_ds(id).get(verify_account_key_column)
    end

    def skip_status_checks?
      false
    end

    private

    def generate_verify_account_key_value
      @verify_account_key_value = random_key
    end

    def create_verify_account_key
      ds = verify_account_ds
      transaction do
        if ds.empty?
          if e = raised_uniqueness_violation{ds.insert(verify_account_key_insert_hash)}
            # If inserting into the verify account table causes a violation, we can pull the 
            # key from the verify account table, or reraise.
            raise e unless @verify_account_key_value = get_verify_account_key(account_id)
          end
        end
      end
    end

    def verify_account_key_insert_hash
      {verify_account_id_column=>account_id, verify_account_key_column=>verify_account_key_value}
    end

    def create_verify_account_email
      create_email(verify_account_email_subject, verify_account_email_body)
    end

    def verify_account_email_body
      render('verify-account-email')
    end

    def verify_account_ds(id=account_id)
      db[verify_account_table].where(verify_account_id_column=>id)
    end

    def _account_from_verify_account_key(token)
      account_from_key(token, account_unverified_status_value){|id| get_verify_account_key(id)}
    end
  end
end
