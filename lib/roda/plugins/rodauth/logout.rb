class Roda
  module RodaPlugins
    module Rodauth
      Logout = Feature.define(:logout)
      Logout.module_eval do
        route 'logout'
        auth_value_methods :logout_redirect

        get_block do |r|
          rodauth.view('logout', 'Logout')
        end

        post_block do |r|
          auth = rodauth
          auth.clear_session
          r.redirect auth.logout_redirect
        end

        def logout_redirect
          "#{prefix}/login"
        end
      end
    end
  end
end
