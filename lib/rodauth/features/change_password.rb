module Rodauth
  ChangePassword = Feature.define(:change_password) do
    route 'change-password'
    notice_flash 'Your password has been changed'
    error_flash 'There was an error changing your password'
    view 'change-password', 'Change Password'
    after
    additional_form_tags
    button 'Change Password'
    redirect
    require_account

    auth_value_method :new_password_label, 'New Password'
    auth_value_method :new_password_param, 'new_password'
    auth_value_method :change_password_requires_password?, true

    get_block do |r, auth|
      auth.change_password_view
    end

    post_block do |r, auth|
      if !auth.change_password_requires_password? || auth.password_match?(r[auth.password_param].to_s)
        password = r[auth.new_password_param].to_s
        if password == r[auth.password_confirm_param].to_s
          if auth.password_meets_requirements?(password)
            auth.transaction do
              auth.set_password(password)
              auth.after_change_password
            end
            auth.set_notice_flash auth.change_password_notice_flash
            r.redirect(auth.change_password_redirect)
          else
            @new_password_error = auth.password_does_not_meet_requirements_message
          end
        else
          @new_password_error = auth.passwords_do_not_match_message
        end
      else
        @password_error = auth.invalid_password_message
      end

      auth.set_error_flash auth.change_password_error_flash
      auth.change_password_view
    end
  end
end
