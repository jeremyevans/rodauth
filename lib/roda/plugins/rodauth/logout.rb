class Roda
  module RodaPlugins
    module Rodauth
      Logout = Feature.define(:logout) do
        route 'logout'
        notice_flash "You have been logged out"
        view 'logout', 'Logout'
        additional_form_tags
        redirect{require_login_redirect}
        require_login

        get_block do |r|
          rodauth.logout_view
        end

        post_block do |r|
          auth = rodauth
          auth.clear_session
          auth.set_notice_flash auth.logout_notice_flash
          r.redirect auth.logout_redirect
        end
      end
    end
  end
end
