class Roda
  module RodaPlugins
    module Rodauth
      Logout = Feature.define(:logout)
      Logout.module_eval do
        auth_block_methods :logout_post
        auth_value_methods :logout_route, :logout_redirect

        Logout::BLOCK = proc do |r|
          auth = rodauth
          r.is auth.logout_route do
            r.get do
              auth.view('logout', 'Logout')
            end

            r.post do
              instance_exec(r, &auth.logout_post_block)
            end
          end
        end

        def logout_route_block
          Logout::BLOCK
        end

        Logout::POST = proc do |r|
          auth = rodauth
          auth.clear_session
          r.redirect auth.logout_redirect
        end

        def logout_post_block
          Logout::POST
        end

        def logout_route
          'logout'
        end

        def logout_redirect
          "#{prefix}/login"
        end
      end
    end
  end
end

