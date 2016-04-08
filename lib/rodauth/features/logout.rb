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

    get_block do
      logout_view
    end

    post_block do
      transaction do
        before_logout
        logout
        after_logout
      end
      set_notice_flash logout_notice_flash
      redirect logout_redirect
    end

    def logout
      clear_session
    end

    def check_before_logout_route
      nil
    end
  end
end
