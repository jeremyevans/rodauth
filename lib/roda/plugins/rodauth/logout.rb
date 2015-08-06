class Roda
  module RodaPlugins
    module Rodauth
      Logout = Feature.define(:logout) do
        route 'logout'
        notice_flash "You have been logged out"
        view 'logout', 'Logout'
        additional_form_tags
        after
        button 'Logout'
        redirect{require_login_redirect}

        auth_methods :logout, :after_logout

        get_block do |r, auth|
          auth.logout_view
        end

        post_block do |r, auth|
          auth.logout
          auth.after_logout
          auth.set_notice_flash auth.logout_notice_flash
          r.redirect auth.logout_redirect
        end

        def logout
          clear_session
        end

        def check_before_logout
          nil
        end
      end
    end
  end
end
