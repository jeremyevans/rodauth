# frozen-string-literal: true

require 'webauthn'

module Rodauth
  Feature.define(:webauthn, :Webauthn) do
    depends :two_factor_base

    loaded_templates %w'webauthn-setup webauthn-auth webauthn-remove'

    view 'webauthn-setup', 'Setup WebAuthn Authentication', 'webauthn_setup'
    view 'webauthn-auth', 'Authenticate Using WebAuthn', 'webauthn_auth'
    view 'webauthn-remove', 'Remove WebAuthn Authenticator', 'webauthn_remove'

    additional_form_tags 'webauthn_setup'
    additional_form_tags 'webauthn_auth'
    additional_form_tags 'webauthn_remove'

    before :webauthn_setup
    before :webauthn_auth
    before :webauthn_remove

    after :webauthn_setup
    after :webauthn_auth_failure
    after :webauthn_remove

    button 'Setup WebAuthn Authentication', 'webauthn_setup'
    button 'Authenticate Using WebAuthn', 'webauthn_auth'
    button 'Remove WebAuthn Authenticator', 'webauthn_remove'

    redirect :webauthn_setup
    redirect :webauthn_remove
    response :webauthn_setup
    response :webauthn_remove

    notice_flash "WebAuthn authentication is now setup", 'webauthn_setup'
    notice_flash "WebAuthn authenticator has been removed", 'webauthn_remove'

    error_flash "Error setting up WebAuthn authentication", 'webauthn_setup'
    error_flash "Error authenticating using WebAuthn", 'webauthn_auth'
    error_flash 'This account has not been setup for WebAuthn authentication', 'webauthn_not_setup'
    error_flash "Error removing WebAuthn authenticator", 'webauthn_remove'

    session_key :authenticated_webauthn_id_session_key, :webauthn_id

    translatable_method :webauthn_auth_link_text, "Authenticate Using WebAuthn"
    translatable_method :webauthn_setup_link_text, "Setup WebAuthn Authentication"
    translatable_method :webauthn_remove_link_text, "Remove WebAuthn Authenticator"

    auth_value_method :webauthn_setup_param, 'webauthn_setup'
    auth_value_method :webauthn_auth_param, 'webauthn_auth'
    auth_value_method :webauthn_remove_param, 'webauthn_remove'
    auth_value_method :webauthn_setup_challenge_param, 'webauthn_setup_challenge'
    auth_value_method :webauthn_setup_challenge_hmac_param, 'webauthn_setup_challenge_hmac'
    auth_value_method :webauthn_auth_challenge_param, 'webauthn_auth_challenge'
    auth_value_method :webauthn_auth_challenge_hmac_param, 'webauthn_auth_challenge_hmac'

    auth_value_method :webauthn_keys_account_id_column, :account_id
    auth_value_method :webauthn_keys_webauthn_id_column, :webauthn_id
    auth_value_method :webauthn_keys_public_key_column, :public_key
    auth_value_method :webauthn_keys_sign_count_column, :sign_count
    auth_value_method :webauthn_keys_last_use_column, :last_use
    auth_value_method :webauthn_keys_table, :account_webauthn_keys

    auth_value_method :webauthn_user_ids_account_id_column, :id
    auth_value_method :webauthn_user_ids_webauthn_id_column, :webauthn_id
    auth_value_method :webauthn_user_ids_table, :account_webauthn_user_ids

    auth_value_method :webauthn_setup_js, File.binread(File.expand_path('../../../../javascript/webauthn_setup.js', __FILE__)).freeze
    auth_value_method :webauthn_auth_js, File.binread(File.expand_path('../../../../javascript/webauthn_auth.js', __FILE__)).freeze
    auth_value_method :webauthn_js_host, ''

    auth_value_method :webauthn_setup_timeout, 120000
    auth_value_method :webauthn_auth_timeout, 60000
    auth_value_method :webauthn_user_verification, 'discouraged'
    auth_value_method :webauthn_attestation, 'none'

    auth_value_method :webauthn_not_setup_error_status, 403

    translatable_method :webauthn_invalid_setup_param_message, "invalid webauthn setup param"
    translatable_method :webauthn_duplicate_webauthn_id_message, "attempt to insert duplicate webauthn id"
    translatable_method :webauthn_invalid_auth_param_message, "invalid webauthn authentication param"
    translatable_method :webauthn_invalid_sign_count_message, "webauthn credential has invalid sign count"
    translatable_method :webauthn_invalid_remove_param_message, "must select valid webauthn authenticator to remove"

    auth_value_methods(
      :webauthn_authenticator_selection,
      :webauthn_extensions,
      :webauthn_origin,
      :webauthn_rp_id,
      :webauthn_rp_name,
    )

    auth_methods(
      :account_webauthn_ids,
      :account_webauthn_usage,
      :account_webauthn_user_id,
      :add_webauthn_credential,
      :authenticated_webauthn_id,
      :handle_webauthn_sign_count_verification_error,
      :new_webauthn_credential,
      :remove_webauthn_key,
      :remove_all_webauthn_keys_and_user_ids,
      :valid_new_webauthn_credential?,
      :valid_webauthn_credential_auth?,
      :webauthn_auth_js_path,
      :webauthn_credential_options_for_get,
      :webauthn_key_insert_hash,
      :webauthn_remove_authenticated_session,
      :webauthn_setup_js_path,
      :webauthn_update_session,
      :webauthn_user_name,
    )

    def_deprecated_alias :webauthn_credential_options_for_get, :webauth_credential_options_for_get

    internal_request_method :webauthn_setup_params
    internal_request_method :webauthn_setup
    internal_request_method :webauthn_auth_params
    internal_request_method :webauthn_auth
    internal_request_method :webauthn_remove

    route(:webauthn_auth_js) do |r|
      before_webauthn_auth_js_route
      r.get do
        set_response_header('content-type', 'text/javascript')
        webauthn_auth_js
      end
    end

    route(:webauthn_auth) do |r|
      require_login
      require_account_session
      require_two_factor_not_authenticated('webauthn')
      require_webauthn_setup
      before_webauthn_auth_route

      r.get do
        webauthn_auth_view
      end

      r.post do
        catch_error do
          webauthn_credential = webauthn_auth_credential_from_form_submission
          transaction do
            before_webauthn_auth
            webauthn_update_session(webauthn_credential.id)
            two_factor_authenticate('webauthn')
          end
        end

        after_webauthn_auth_failure
        set_error_flash webauthn_auth_error_flash
        webauthn_auth_view
      end
    end

    route(:webauthn_setup_js) do |r|
      before_webauthn_setup_js_route
      r.get do
        set_response_header('content-type', 'text/javascript')
        webauthn_setup_js
      end
    end
    
    route(:webauthn_setup) do |r|
      require_authentication unless two_factor_login_type_match?('webauthn')
      require_account_session
      before_webauthn_setup_route

      r.get do
        webauthn_setup_view
      end

      r.post do
        catch_error do
          webauthn_credential = webauthn_setup_credential_from_form_submission
          throw_error = false

          transaction do
            before_webauthn_setup

            if raises_uniqueness_violation?{add_webauthn_credential(webauthn_credential)}
              throw_error = true
              raise Sequel::Rollback
            end

            unless two_factor_authenticated?
              webauthn_update_session(webauthn_credential.id)
              two_factor_update_session('webauthn')
            end
            after_webauthn_setup
          end

          if throw_error
            throw_error_reason(:duplicate_webauthn_id, invalid_field_error_status, webauthn_setup_param, webauthn_duplicate_webauthn_id_message)
          end

          webauthn_setup_response
        end

        set_error_flash webauthn_setup_error_flash
        webauthn_setup_view
      end
    end

    route(:webauthn_remove) do |r|
      require_authentication unless two_factor_login_type_match?('webauthn')
      require_account_session
      require_webauthn_setup
      before_webauthn_remove_route

      r.get do
        webauthn_remove_view
      end

      r.post do
        catch_error do
          unless webauthn_id = param_or_nil(webauthn_remove_param)
            throw_error_reason(:invalid_webauthn_remove_param, invalid_field_error_status, webauthn_remove_param, webauthn_invalid_remove_param_message)
          end

          unless two_factor_password_match?(param(password_param))
            throw_error_reason(:invalid_password, invalid_password_error_status, password_param, invalid_password_message)
          end

          transaction do
            before_webauthn_remove
            unless remove_webauthn_key(webauthn_id)
              throw_error_reason(:invalid_webauthn_remove_param, invalid_field_error_status, webauthn_remove_param, webauthn_invalid_remove_param_message)
            end
            if authenticated_webauthn_id == webauthn_id && two_factor_login_type_match?('webauthn')
              webauthn_remove_authenticated_session
              two_factor_remove_session('webauthn')
            end
            after_webauthn_remove
          end

          webauthn_remove_response
        end

        set_error_flash webauthn_remove_error_flash
        webauthn_remove_view
      end
    end

    def webauthn_auth_form_path
      webauthn_auth_path
    end

    def authenticated_webauthn_id
      session[authenticated_webauthn_id_session_key]
    end

    def webauthn_remove_authenticated_session
      remove_session_value(authenticated_webauthn_id_session_key)
    end

    def webauthn_update_session(webauthn_id)
      set_session_value(authenticated_webauthn_id_session_key, webauthn_id)
    end

    def webauthn_authenticator_selection
      {'requireResidentKey' => false, 'userVerification' => webauthn_user_verification}
    end

    def webauthn_extensions
      {}
    end

    def account_webauthn_ids
      webauthn_keys_ds.select_map(webauthn_keys_webauthn_id_column)
    end

    def account_webauthn_usage
      webauthn_keys_ds.select_hash(webauthn_keys_webauthn_id_column, webauthn_keys_last_use_column)
    end

    def account_webauthn_user_id
      unless webauthn_id = webauthn_user_ids_ds.get(webauthn_user_ids_webauthn_id_column)
        webauthn_id = WebAuthn.generate_user_id
        if e = raised_uniqueness_violation do
              webauthn_user_ids_ds.insert(
                webauthn_user_ids_account_id_column => webauthn_account_id,
                webauthn_user_ids_webauthn_id_column => webauthn_id
              )
            end
          # If two requests to create a webauthn user id are sent at the same time and an insert
          # is attempted for both, one will fail with a unique constraint violation.  In that case
          # it is safe for the second one to use the webauthn user id inserted by the other request.
          # If there is still no webauthn user id at this point, then we'll just reraise the
          # exception.
          # :nocov:
          raise e unless webauthn_id = webauthn_user_ids_ds.get(webauthn_user_ids_webauthn_id_column)
          # :nocov:
        end
      end

      webauthn_id
    end

    def new_webauthn_credential
      WebAuthn::Credential.options_for_create(
        :timeout => webauthn_setup_timeout,
        :user => {:id=>account_webauthn_user_id, :name=>webauthn_user_name},
        :authenticator_selection => webauthn_authenticator_selection,
        :attestation => webauthn_attestation,
        :extensions => webauthn_extensions,
        :exclude => account_webauthn_ids,
        **webauthn_create_relying_party_opts
      )
    end

    def valid_new_webauthn_credential?(webauthn_credential)
      _override_webauthn_credential_response_verify(webauthn_credential)
      (challenge = param_or_nil(webauthn_setup_challenge_param)) &&
        (hmac = param_or_nil(webauthn_setup_challenge_hmac_param)) &&
        (timing_safe_eql?(compute_hmac(challenge), hmac) || (hmac_secret_rotation? && timing_safe_eql?(compute_old_hmac(challenge), hmac))) &&
        webauthn_credential.verify(challenge)
    end

    def webauthn_credential_options_for_get
      WebAuthn::Credential.options_for_get(
        :allow => webauthn_allow,
        :timeout => webauthn_auth_timeout,
        :user_verification => webauthn_user_verification,
        :extensions => webauthn_extensions,
        **webauthn_get_relying_party_opts
      )
    end

    def webauthn_user_name
      account![login_column]
    end

    def webauthn_origin
      base_url
    end

    def webauthn_allow
      account_webauthn_ids
    end

    def webauthn_rp_id
      webauthn_origin.sub(/\Ahttps?:\/\//, '').sub(/:\d+\z/, '')
    end

    def webauthn_rp_name
      webauthn_rp_id
    end

    def handle_webauthn_sign_count_verification_error
      throw_error_reason(:invalid_webauthn_sign_count, invalid_field_error_status, webauthn_auth_param, webauthn_invalid_sign_count_message) 
    end

    def add_webauthn_credential(webauthn_credential)
      webauthn_keys_ds.insert(webauthn_key_insert_hash(webauthn_credential))
      super if defined?(super)
      nil
    end

    def valid_webauthn_credential_auth?(webauthn_credential)
      ds = webauthn_keys_ds.where(webauthn_keys_webauthn_id_column => webauthn_credential.id)
      pub_key, sign_count = ds.get([webauthn_keys_public_key_column, webauthn_keys_sign_count_column])

      _override_webauthn_credential_response_verify(webauthn_credential)
      (challenge = param_or_nil(webauthn_auth_challenge_param)) &&
        (hmac = param_or_nil(webauthn_auth_challenge_hmac_param)) &&
        (timing_safe_eql?(compute_hmac(challenge), hmac) || (hmac_secret_rotation? && timing_safe_eql?(compute_old_hmac(challenge), hmac))) &&
        webauthn_credential.verify(challenge, public_key: pub_key, sign_count: sign_count) &&
        ds.update(
          webauthn_keys_sign_count_column => Integer(webauthn_credential.sign_count),
          webauthn_keys_last_use_column => Sequel::CURRENT_TIMESTAMP
        ) == 1
    end

    def remove_webauthn_key(webauthn_id)
      webauthn_keys_ds.where(webauthn_keys_webauthn_id_column=>webauthn_id).delete == 1
    end

    def remove_all_webauthn_keys_and_user_ids
      webauthn_user_ids_ds.delete
      webauthn_keys_ds.delete
    end

    def webauthn_setup?
      !webauthn_keys_ds.empty?
    end

    def require_webauthn_setup
      unless webauthn_setup?
        set_redirect_error_status(webauthn_not_setup_error_status)
        set_error_reason :webauthn_not_setup
        set_redirect_error_flash webauthn_not_setup_error_flash
        redirect two_factor_need_setup_redirect
      end
    end

    def two_factor_remove
      super
      remove_all_webauthn_keys_and_user_ids
    end

    def possible_authentication_methods
      methods = super
      methods << 'webauthn' if webauthn_setup?
      methods
    end

    private

    if WebAuthn::VERSION >= '3'
      if WebAuthn::RelyingParty.instance_method(:initialize).parameters.include?([:key, :allowed_origins])
        def webauthn_relying_party
          # No need to memoize, only called once per request
          WebAuthn::RelyingParty.new(
            allowed_origins: [webauthn_origin],
            id: webauthn_rp_id,
            name: webauthn_rp_name,
          )
        end
      # :nocov:
      else
        def webauthn_relying_party
          WebAuthn::RelyingParty.new(
            origin: webauthn_origin,
            id: webauthn_rp_id,
            name: webauthn_rp_name,
          )
        end
      # :nocov:
      end

      def webauthn_create_relying_party_opts
        { :relying_party => webauthn_relying_party }
      end
      alias webauthn_get_relying_party_opts webauthn_create_relying_party_opts

      def webauthn_form_submission_call(meth, arg)
        WebAuthn::Credential.public_send(meth, arg, :relying_party => webauthn_relying_party)
      end

      def _override_webauthn_credential_response_verify(webauthn_credential)
        # no need to override
      end
    # :nocov:
    else
      def webauthn_create_relying_party_opts
        {:rp => {:name=>webauthn_rp_name, :id=>webauthn_rp_id}}
      end

      def webauthn_get_relying_party_opts
        { :rp_id => webauthn_rp_id }
      end

      def webauthn_form_submission_call(meth, arg)
        WebAuthn::Credential.public_send(meth, arg)
      end

      def _override_webauthn_credential_response_verify(webauthn_credential)
        # Hack around inability to override expected_origin and rp_id
        origin = webauthn_origin
        rp_id = webauthn_rp_id
        webauthn_credential.response.define_singleton_method(:verify) do |expected_challenge, expected_origin = nil, **kw|
          kw[:rp_id] = rp_id
          super(expected_challenge, expected_origin || origin, **kw)
        end
      end
    # :nocov:
    end

    def _two_factor_auth_links
      links = super
      links << [10, webauthn_auth_path, webauthn_auth_link_text] if webauthn_setup? && !two_factor_login_type_match?('webauthn')
      links
    end

    def _two_factor_setup_links
      super << [10, webauthn_setup_path, webauthn_setup_link_text]
    end

    def _two_factor_remove_links
      links = super
      links << [10, webauthn_remove_path, webauthn_remove_link_text] if webauthn_setup?
      links
    end

    def _two_factor_remove_all_from_session
      two_factor_remove_session('webauthn')
      remove_session_value(authenticated_webauthn_id_session_key)
      super
    end

    def webauthn_key_insert_hash(webauthn_credential)
      {
        webauthn_keys_account_id_column => webauthn_account_id,
        webauthn_keys_webauthn_id_column => webauthn_credential.id,
        webauthn_keys_public_key_column => webauthn_credential.public_key,
        webauthn_keys_sign_count_column => Integer(webauthn_credential.sign_count)
      }
    end

    def webauthn_account_id
      session_value
    end

    def webauthn_user_ids_ds
      db[webauthn_user_ids_table].where(webauthn_user_ids_account_id_column => webauthn_account_id)
    end

    def webauthn_keys_ds
      db[webauthn_keys_table].where(webauthn_keys_account_id_column => webauthn_account_id)
    end

    def webauthn_auth_credential_from_form_submission
      begin
        webauthn_credential = webauthn_form_submission_call(:from_get, webauthn_auth_data)

        unless valid_webauthn_credential_auth?(webauthn_credential)
          throw_error_reason(:invalid_webauthn_auth_param, invalid_key_error_status, webauthn_auth_param, webauthn_invalid_auth_param_message)
        end
      rescue WebAuthn::SignCountVerificationError
        handle_webauthn_sign_count_verification_error
      rescue WebAuthn::Error, RuntimeError, NoMethodError
        throw_error_reason(:invalid_webauthn_auth_param, invalid_field_error_status, webauthn_auth_param, webauthn_invalid_auth_param_message) 
      end

      webauthn_credential
    end

    def webauthn_auth_data
      case auth_data = raw_param(webauthn_auth_param)
      when String
        begin
          JSON.parse(auth_data)
        rescue
          throw_error_reason(:invalid_webauthn_auth_param, invalid_field_error_status, webauthn_auth_param, webauthn_invalid_auth_param_message) 
        end
      when Hash
        auth_data
      else
        throw_error_reason(:invalid_webauthn_auth_param, invalid_field_error_status, webauthn_auth_param, webauthn_invalid_auth_param_message)
      end
    end

    def webauthn_setup_credential_from_form_submission
      unless two_factor_password_match?(param(password_param))
        throw_error_reason(:invalid_password, invalid_password_error_status, password_param, invalid_password_message)
      end

      begin
        webauthn_credential = webauthn_form_submission_call(:from_create, webauthn_setup_data)

        unless valid_new_webauthn_credential?(webauthn_credential)
          throw_error_reason(:invalid_webauthn_setup_param, invalid_field_error_status, webauthn_setup_param, webauthn_invalid_setup_param_message) 
        end
      rescue WebAuthn::Error, RuntimeError, NoMethodError
        throw_error_reason(:invalid_webauthn_setup_param, invalid_field_error_status, webauthn_setup_param, webauthn_invalid_setup_param_message) 
      end

      webauthn_credential
    end

    def webauthn_setup_data
      case setup_data = raw_param(webauthn_setup_param)
      when String
        begin
          JSON.parse(setup_data)
        rescue
          throw_error_reason(:invalid_webauthn_setup_param, invalid_field_error_status, webauthn_setup_param, webauthn_invalid_setup_param_message) 
        end
      when Hash
        setup_data
      else
        throw_error_reason(:invalid_webauthn_setup_param, invalid_field_error_status, webauthn_setup_param, webauthn_invalid_setup_param_message)
      end
    end
  end
end
