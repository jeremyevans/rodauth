module Rodauth
  Logout = Feature.define(:logout) do
    route 'logout'
    notice_flash "You have been logged out"
    view 'logout', 'Logout'
    additional_form_tags
    before
    after
    button 'Logout'
    redirect{require_login_redirect}

    auth_methods :logout

    get_block do |r, auth|
      auth.logout_view
    end

    post_block do |r, auth|
      auth.transaction do
        auth.before_logout
        auth.logout
        auth.after_logout
      end
      auth.set_notice_flash auth.logout_notice_flash
      auth.redirect auth.logout_redirect
    end

    def logout
      clear_session
    end

    def check_before_logout
      nil
    end
  end
end
