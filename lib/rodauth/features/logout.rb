module Rodauth
  Logout = Feature.define(:logout) do
    notice_flash "You have been logged out"
    view 'logout', 'Logout'
    additional_form_tags
    before
    after
    button 'Logout'
    redirect{require_login_redirect}

    auth_methods :logout

    route do |r|
      before_logout_route

      r.get do
        logout_view
      end

      r.post do
        transaction do
          before_logout
          logout
          after_logout
        end
        set_notice_flash logout_notice_flash
        redirect logout_redirect
      end
    end

    def logout
      clear_session
    end
  end
end
