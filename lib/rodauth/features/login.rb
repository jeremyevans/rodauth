# frozen-string-literal: true

module Rodauth
  Feature.define(:login, :Login) do
    notice_flash "You have been logged in"
    notice_flash "Login recognized, please enter your password", "need_password"
    error_flash "There was an error logging in"
    loaded_templates %w'login login-field password-field login-display'
    view 'login', 'Login'
    additional_form_tags
    button 'Login'
    redirect

    auth_value_method :login_error_status, 401
    auth_value_method :login_form_footer, ''
    auth_value_method :use_multi_phase_login?, false

    route do |r|
      check_already_logged_in
      before_login_route

      r.get do
        login_view
      end

      r.post do
        clear_session
        skip_error_flash = false

        catch_error do
          unless account_from_login(param(login_param))
            throw_error_status(no_matching_login_error_status, login_param, no_matching_login_message)
          end

          before_login_attempt

          unless open_account?
            throw_error_status(unopen_account_error_status, login_param, unverified_account_message)
          end

          if use_multi_phase_login?
            @valid_login_entered = true

            unless param_or_nil(password_param)
              after_login_entered_during_multi_phase_login
              skip_error_flash = true
              next
            end
          end

          unless password_match?(param(password_param))
            after_login_failure
            throw_error_status(login_error_status, password_param, invalid_password_message)
          end

          _login
        end

        set_error_flash login_error_flash unless skip_error_flash
        login_view
      end
    end

    attr_reader :login_form_header

    def after_login_entered_during_multi_phase_login
      set_notice_now_flash need_password_notice_flash
    end

    def skip_login_field_on_login?
      return false unless use_multi_phase_login?
      @valid_login_entered
    end

    def skip_password_field_on_login?
      return false unless use_multi_phase_login?
      @valid_login_entered != true
    end

    def login_hidden_field
      "<input type='hidden' name=\"#{login_param}\" value=\"#{scope.h param(login_param)}\" />"
    end

    private

    def _login
      transaction do
        before_login
        update_session
        after_login
      end
      set_notice_flash login_notice_flash
      redirect login_redirect
    end
  end
end
