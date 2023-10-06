# frozen-string-literal: true

module Rodauth
  Feature.define(:logout, :Logout) do
    notice_flash "You have been logged out"
    loaded_templates %w'logout'
    view 'logout', 'Logout'
    additional_form_tags
    before
    after
    button 'Logout'
    redirect{require_login_redirect}
    response

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
        logout_response
      end
    end

    def logout
      clear_session
    end
  end
end
