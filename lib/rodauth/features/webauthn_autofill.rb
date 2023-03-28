# frozen-string-literal: true

module Rodauth
  Feature.define(:webauthn_autofill, :WebauthnAutofill) do
    depends :webauthn_login

    auth_value_method :webauthn_autofill_js, File.binread(File.expand_path('../../../../javascript/webauthn_autofill.js', __FILE__)).freeze

    route(:webauthn_autofill_js) do |r|
      before_webauthn_autofill_js_route
      r.get do
        response['Content-Type'] = 'text/javascript'
        webauthn_autofill_js
      end
    end

    def webauthn_allow
      return [] unless logged_in? || account
      super
    end

    def webauthn_user_verification
      'preferred'
    end

    def webauthn_authenticator_selection
      super.merge({ 'residentKey' => 'required', 'requireResidentKey' => true })
    end

    def login_field_autocomplete_value
      request.path_info == login_path ? "#{super} webauthn" : super
    end

    private

    def _login_form_footer
      footer = super
      footer += render("webauthn-autofill") unless valid_login_entered?
      footer
    end

    def account_from_webauthn_login
      return super if param_or_nil(login_param)

      credential_id = webauthn_auth_data["id"]
      account_id = db[webauthn_keys_table]
        .where(webauthn_keys_webauthn_id_column => credential_id)
        .get(webauthn_keys_account_id_column)

      @account = account_ds(account_id).first if account_id
    end

    def webauthn_login_options?
      return true unless param_or_nil(login_param)
      super
    end
  end
end
