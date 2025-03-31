# frozen-string-literal: true

module Rodauth
  Feature.define(:login, :Login) do
    notice_flash "You have been logged in"
    notice_flash "Login recognized, please enter your password", "need_password"
    error_flash "There was an error logging in"
    loaded_templates %w'login login-form login-form-footer multi-phase-login login-field password-field login-display'
    view 'login', 'Login'
    view 'multi-phase-login', 'Login', 'multi_phase_login'
    additional_form_tags
    button 'Login'
    redirect

    auth_value_method :login_error_status, 401
    translatable_method :login_form_footer_links_heading, '<h2 class="rodauth-login-form-footer-links-heading">Other Options</h2>'
    auth_value_method :login_return_to_requested_location?, false
    auth_value_method :login_return_to_requested_location_max_path_size, 2048
    auth_value_method :use_multi_phase_login?, false

    session_key :login_redirect_session_key, :login_redirect

    auth_cached_method :multi_phase_login_forms
    auth_cached_method :login_form_footer

    auth_value_methods :login_return_to_requested_location_path

    auth_private_methods(
      :login_form_footer_links,
      :login_response
    )

    internal_request_method
    internal_request_method :valid_login_and_password?

    route do |r|
      check_already_logged_in
      before_login_route

      r.get do
        login_view
      end

      r.post do
        skip_error_flash = false
        view = :login_view

        catch_error do
          unless account_from_login(login_param_value)
            throw_error_reason(:no_matching_login, no_matching_login_error_status, login_param, no_matching_login_message)
          end

          before_login_attempt

          unless open_account?
            throw_error_reason(:unverified_account, unopen_account_error_status, login_param, unverified_account_message)
          end

          if use_multi_phase_login?
            @valid_login_entered = true
            view = :multi_phase_login_view

            unless param_or_nil(password_param)
              after_login_entered_during_multi_phase_login
              skip_error_flash = true
              next
            end
          end

          unless password_match?(param(password_param))
            after_login_failure
            throw_error_reason(:invalid_password, login_error_status, password_param, invalid_password_message)
          end

          login('password')
        end

        set_error_flash login_error_flash unless skip_error_flash
        send(view)
      end
    end

    attr_reader :login_form_header
    attr_reader :saved_login_redirect
    private :saved_login_redirect

    def login(auth_type)
      @saved_login_redirect = remove_session_value(login_redirect_session_key)
      transaction do
        before_login
        login_session(auth_type)
        yield if block_given?
        after_login
      end
      require_response(:_login_response)
    end

    def login_required
      if login_return_to_requested_location? && (path = login_return_to_requested_location_path) && path.bytesize <= login_return_to_requested_location_max_path_size
        set_session_value(login_redirect_session_key, path)
      end
      super
    end

    def login_return_to_requested_location_path
      request.fullpath if request.get?
    end

    def after_login_entered_during_multi_phase_login
      set_notice_now_flash need_password_notice_flash
      if multi_phase_login_forms.length == 1 && (meth = multi_phase_login_forms[0][2])
        send(meth)
      end
    end

    def skip_login_field_on_login?
      return false unless use_multi_phase_login?
      valid_login_entered?
    end

    def skip_password_field_on_login?
      return false unless use_multi_phase_login?
      !valid_login_entered?
    end

    def valid_login_entered?
      @valid_login_entered
    end

    def login_hidden_field
      "<input type='hidden' name=\"#{login_param}\" value=\"#{scope.h param(login_param)}\" />"
    end

    def login_form_footer_links
      @login_form_footer_links ||= _filter_links(_login_form_footer_links)
    end

    def render_multi_phase_login_forms
      multi_phase_login_forms.sort.map{|_, form, _| form}.join("\n")
    end

    def require_login_redirect
      login_path
    end

    private

    def _login_response
      set_notice_flash login_notice_flash
      redirect(saved_login_redirect || login_redirect)
    end

    def _login_form_footer_links
      []
    end

    def _multi_phase_login_forms
      forms = []
      forms << [10, render("login-form"), nil] if has_password?
      forms
    end

    def _login_form_footer
      return '' if _login_form_footer_links.empty?
      render('login-form-footer')
    end

    def _login(auth_type)
      warn("Deprecated #_login method called, use #login instead.")
      login(auth_type)
    end
  end
end
