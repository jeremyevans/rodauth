class Roda
  module RodaPlugins
    module Rodauth
      Logout = Feature.define(:logout) do
        route 'logout'
        notice_flash "You have been logged out"
        auth_value_methods :logout_redirect

        get_block do |r|
          rodauth.view('logout', 'Logout')
        end

        post_block do |r|
          auth = rodauth
          auth.clear_session
          auth.set_notice_flash auth.logout_notice_flash
          r.redirect auth.logout_redirect
        end

        def logout_redirect
          "#{prefix}/login"
        end
      end
    end
  end
end
