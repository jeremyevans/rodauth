class Roda
  module RodaPlugins
    module Rodauth
      Login = Feature.define(:login)
      Login.module_eval do
        auth_block_methods :login_post
        auth_value_methods :no_matching_login_message, :invalid_password_message, :login_route, :login_redirect
        auth_methods :account_from_login, :update_session, :password_match?, :session_value

        Login::ROUTE = proc do |r|
          auth = rodauth
          r.is auth.login_route do
            r.get do
              auth.view('login', 'Login')
            end

            r.post do
              instance_exec(r, &auth.login_post_block)
            end
          end
        end

        def login_route_block
          Login::ROUTE
        end

        Login::POST = proc do |r|
          auth = rodauth
          auth.clear_session

          if auth.account_from_login(r[auth.login_param].to_s)
            if auth.password_match?(r[auth.password_param].to_s)
              auth.update_session
              r.redirect auth.login_redirect
            else
              if auth.allow_password_reset?
                @password_reset_login = r[auth.login_param].to_s
              end
              @password_error = auth.invalid_password_message
            end
          else
            @login_error = auth.no_matching_login_message
          end

          auth.view('login', 'Login')
        end

        def login_post_block
          Login::POST
        end

        def login_route
          'login'
        end

        def login_redirect
          '/'
        end

        def no_matching_login_message
          "no matching login"
        end

        def invalid_password_message
          "invalid password"
        end

        def session_value
          account.send(account_id)
        end

        def account_from_login(login)
          @account = account_model.where(login_column=>login, account_status_id=>account_open_status_value).first
        end

        def update_session
          session[session_key] = session_value
        end

        def password_match?(password)
          account_model.db.get{|db| db.account_valid_password(account.send(account_id), password)}
        end
      end
    end
  end
end
