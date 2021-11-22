# frozen-string-literal: true

module Rodauth
  Feature.define(:json, :Json) do
    translatable_method :json_not_accepted_error_message, 'Unsupported Accept header. Must accept "application/json" or compatible content type'
    translatable_method :json_non_post_error_message, 'non-POST method used in JSON API'
    auth_value_method :json_accept_regexp, /(?:(?:\*|\bapplication)\/\*|\bapplication\/(?:vnd\.api\+)?json\b)/i
    auth_value_method :json_check_accept?, true
    auth_value_method :json_request_content_type_regexp, /\bapplication\/(?:vnd\.api\+)?json\b/i
    auth_value_method :json_response_content_type, 'application/json'
    auth_value_method :json_response_custom_error_status?, true
    auth_value_method :json_response_error_status, 400
    auth_value_method :json_response_error_key, "error"
    auth_value_method :json_response_field_error_key, "field-error"
    auth_value_method :json_response_success_key, "success"
    translatable_method :non_json_request_error_message, 'Only JSON format requests are allowed'

    auth_value_methods(
      :only_json?,
      :use_json?,
    )

    auth_methods(
      :json_request?,
    )

    auth_private_methods :json_response_body

    def set_field_error(field, message)
      return super unless use_json?
      json_response[json_response_field_error_key] = [field, message]
    end

    def set_error_flash(message)
      return super unless use_json?
      json_response[json_response_error_key] = message
    end

    def set_redirect_error_flash(message)
      return super unless use_json?
      json_response[json_response_error_key] = message
    end

    def set_notice_flash(message)
      return super unless use_json?
      json_response[json_response_success_key] = message if include_success_messages?
    end

    def set_notice_now_flash(message)
      return super unless use_json?
      json_response[json_response_success_key] = message if include_success_messages?
    end

    def json_request?
      return @json_request if defined?(@json_request)
      @json_request = request.content_type =~ json_request_content_type_regexp
    end

    def use_json?
      json_request? || only_json?
    end

    def view(page, title)
      return super unless use_json?
      return_json_response
    end

    private

    def before_two_factor_manage_route
      super if defined?(super)
      if use_json?
        json_response[:setup_links] = two_factor_setup_links.sort.map{|_,link| link}
        json_response[:remove_links] = two_factor_remove_links.sort.map{|_,link| link}
        json_response[json_response_success_key] ||= "" if include_success_messages?
        return_json_response
      end
    end

    def before_two_factor_auth_route
      super if defined?(super)
      if use_json?
        json_response[:auth_links] = two_factor_auth_links.sort.map{|_,link| link}
        json_response[json_response_success_key] ||= "" if include_success_messages?
        return_json_response
      end
    end

    def before_view_recovery_codes
      super if defined?(super)
      if use_json?
        json_response[:codes] = recovery_codes
        json_response[json_response_success_key] ||= "" if include_success_messages?
      end
    end

    def before_webauthn_setup_route
      super if defined?(super)
      if use_json? && !param_or_nil(webauthn_setup_param)
        cred = new_webauthn_credential
        json_response[webauthn_setup_param] = cred.as_json
        json_response[webauthn_setup_challenge_param] = cred.challenge
        json_response[webauthn_setup_challenge_hmac_param] = compute_hmac(cred.challenge)
      end
    end

    def before_webauthn_auth_route
      super if defined?(super)
      if use_json? && !param_or_nil(webauthn_auth_param)
        cred = webauth_credential_options_for_get
        json_response[webauthn_auth_param] = cred.as_json
        json_response[webauthn_auth_challenge_param] = cred.challenge
        json_response[webauthn_auth_challenge_hmac_param] = compute_hmac(cred.challenge)
      end
    end

    def before_webauthn_login_route
      super if defined?(super)
      if use_json? && !param_or_nil(webauthn_auth_param) && account_from_login(param(login_param))
        cred = webauth_credential_options_for_get
        json_response[webauthn_auth_param] = cred.as_json
        json_response[webauthn_auth_challenge_param] = cred.challenge
        json_response[webauthn_auth_challenge_hmac_param] = compute_hmac(cred.challenge)
      end
    end

    def before_webauthn_remove_route
      super if defined?(super)
      if use_json? && !param_or_nil(webauthn_remove_param)
        json_response[webauthn_remove_param] = account_webauthn_usage
      end
    end

    def before_otp_setup_route
      super if defined?(super)
      if use_json? && otp_keys_use_hmac? && !param_or_nil(otp_setup_raw_param)
        _otp_tmp_key(otp_new_secret)
        json_response[otp_setup_param] = otp_user_key
        json_response[otp_setup_raw_param] = otp_key
      end
    end

    def before_rodauth
      if json_request?
        if json_check_accept? && (accept = request.env['HTTP_ACCEPT']) && accept !~ json_accept_regexp
          response.status = 406
          json_response[json_response_error_key] = json_not_accepted_error_message
          _return_json_response
        end

        unless request.post?
          response.status = 405
          response.headers['Allow'] = 'POST'
          json_response[json_response_error_key] = json_non_post_error_message
          return_json_response
        end
      elsif only_json?
        response.status = json_response_error_status
        response.write non_json_request_error_message
        request.halt
      end

      super
    end

    def redirect(_)
      return super unless use_json?
      return_json_response
    end

    def return_json_response
      _return_json_response
    end

    def _return_json_response
      response.status ||= json_response_error_status if json_response[json_response_error_key]
      response['Content-Type'] ||= json_response_content_type
      response.write(_json_response_body(json_response))
      request.halt
    end

    def include_success_messages?
      !json_response_success_key.nil?
    end

    def _json_response_body(hash)
      request.send(:convert_to_json, hash)
    end

    def json_response
      @json_response ||= {}
    end

    def set_redirect_error_status(status)
      if use_json? && json_response_custom_error_status?
        response.status = status
      end
    end

    def set_response_error_status(status)
      if use_json? && !json_response_custom_error_status?
        status = json_response_error_status
      end

      super
    end
  end
end
