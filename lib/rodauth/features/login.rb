# frozen-string-literal: true

module Rodauth
  Feature.define(:login, :Login) do
    notice_flash "You have been logged in"
    error_flash "There was an error logging in"
    loaded_templates %w'login login-field password-field'
    view 'login', 'Login'
    additional_form_tags
    button 'Login'
    redirect

    auth_value_method :login_error_status, 401
    auth_value_method :login_form_footer, ''
    auth_value_method :use_generic_login_errors?, false
    auth_value_method :generic_login_error_status, 401
    auth_value_method :generic_login_error_message, 'there was a problem with the login or password supplied'

    route do |r|
      check_already_logged_in
      before_login_route

      r.get do
        login_view
      end

      r.post do
        clear_session

        catch_error do
          unless account_from_login(param(login_param))
            throw_error_status(error_status(:no_login), error_param(:no_login), error_message(:no_login))
          end

          before_login_attempt

          unless open_account?
            throw_error_status(error_status(:unopened_account), error_param(:unopened_account), error_message(:unopened_account))
          end

          unless password_match?(param(password_param))
            after_login_failure
            throw_error_status(error_status(:invalid_password), error_param(:invalid_password), error_message(:invalid_password))
          end

          transaction do
            before_login
            update_session
            after_login
          end
          set_notice_flash login_notice_flash
          redirect login_redirect
        end

        set_error_flash login_error_flash
        login_view
      end
    end

    attr_reader :login_form_header

    def error_status(type)
      return generic_login_error_status if use_generic_login_errors?

      case type
      when :no_login then login_error_status
      when :unopened_account then unopen_account_error_status
      when :invalid_password then invalid_password_error_status
      end
    end

    def error_param(type)
      return login_param if use_generic_login_errors?

      if type == :invalid_password
        password_param
      else
        login_param
      end
    end

    def error_message(type)
      return generic_login_error_message if use_generic_login_errors?

      case type
      when :no_login then no_matching_login_message
      when :unopened_account then unverified_account_message
      when :invalid_password then invalid_password_message
      end
    end
  end
end
