class Roda
  module RodaPlugins
    module Rodauth
      Remember = Feature.define(:remember) do
        depends :logout
        route 'remember'
        notice_flash "Your remember setting has been updated"
        view 'remember', 'Change Remember Setting'
        additional_form_tags
        button 'Change Remember Setting'
        after
        redirect
        require_account

        auth_value_methods(
          :extend_remember_deadline?,
          :remember_confirm_view,
          :remember_confirm_additional_form_tags,
          :remember_cookie_key,
          :remember_cookie_options,
          :remember_deadline_column,
          :remember_id_column,
          :remember_key_column,
          :remember_period,
          :remember_table,
          :remembered_session_key
        )
        auth_methods(
          :add_remember_key,
          :after_load_memory,
          :after_remember_confirm,
          :clear_remembered_session_key,
          :disable_remember_login,
          :forget_login,
          :generate_remember_key_value,
          :get_remember_key,
          :load_memory,
          :logged_in_via_remember_key?,
          :remember_key_value,
          :remember_login,
          :remove_remember_key
        )

        get_block do |r, auth|
          if r['confirm']
            auth.remember_confirm_view
          else
            auth.remember_view
          end
        end

        post_block do |r, auth|
          if r['confirm']
            if auth._account_from_session && auth.password_match?(r[auth.password_param].to_s)
              auth.transaction do
                auth.clear_remembered_session_key
                auth.after_remember_confirm
              end
              r.redirect auth.remember_confirm_redirect
            else
              @password_error = auth.invalid_password_message
              auth.remember_confirm_view
            end
          else
            auth.transaction do
              case r['remember']
              when 'remember'
                auth.remember_login
              when 'forget'
                auth.forget_login 
              when 'disable'
                auth.disable_remember_login 
              end
              auth.after_remember
            end
            auth.set_notice_flash auth.remember_notice_flash
            r.redirect auth.remember_redirect
          end
        end

        def after_logout
          super
          forget_login
        end

        def after_remember_confirm
        end

        def remember_confirm_view
          view('confirm-password', 'Confirm Password')
        end

        def remember_confirm_button
          'Confirm Password'
        end

        def remember_confirm_redirect
          default_redirect
        end

        def remember_confirm_additional_form_tags
        end

        attr_reader :remember_key_value

        def generate_remember_key_value
          @remember_key_value = random_key
        end

        def after_load_memory
        end

        def load_memory
          return unless session[session_key] || (cookie = request.cookies[remember_cookie_key])
          id, key = cookie.split('_', 2)
          return unless id && key

          id = id.to_i

          return unless actual = active_remember_key_dataset(id).
            get(remember_key_column)

          return unless timing_safe_eql?(key, actual)

          session[session_key] = id
          account_from_session

          session[remembered_session_key] = true
          if extend_remember_deadline?
            active_remember_key_dataset(id).update(:deadline=>Sequel.date_add(:deadline, remember_period))
          end
          after_load_memory
        end

        def remember_login
          get_remember_key
          opts = Hash[remember_cookie_options]
          opts[:value] = "#{account_id_value}_#{remember_key_value}"
          ::Rack::Utils.set_cookie_header!(response.headers, remember_cookie_key, opts)
        end

        def remember_cookie_options
          {}
        end

        def extend_remember_deadline?
          false
        end

        def remember_period
          {:days=>14}
        end

        def forget_login
          ::Rack::Utils.delete_cookie_header!(response.headers, remember_cookie_key, remember_cookie_options)
        end

        def remember_key_dataset(id_value=account_id_value)
          db[remember_table].
            where(remember_id_column=>id_value)
        end
        def active_remember_key_dataset(id_value=account_id_value)
          remember_key_dataset(id_value).where(Sequel.expr(remember_deadline_column) > Sequel::CURRENT_TIMESTAMP)
        end

        def get_remember_key
          unless @remember_key_value = active_remember_key_dataset.get(remember_key_column)
           generate_remember_key_value
           transaction do
             remove_remember_key
             add_remember_key
           end
          end
          nil
        end

        def disable_remember_login
          remove_remember_key
        end

        def add_remember_key
          remember_key_dataset.insert(remember_id_column=>account_id_value, remember_key_column=>remember_key_value)
        end

        def remove_remember_key
          remember_key_dataset.delete
        end

        def remember_id_column
          :id
        end

        def remember_key_column
          :key
        end

        def remember_deadline_column
          :deadline
        end

        def remember_table
          :account_remember_keys
        end

        def remember_cookie_key
          '_remember'
        end

        def clear_remembered_session_key
          session.delete(remembered_session_key)
        end

        def logged_in_via_remember_key?
          !!session[remembered_session_key]
        end

        def remembered_session_key
          :remembered
        end

        def after_close_account
          super
          remove_remember_key
        end

        def post_configure
          super
          begin
            db
          rescue
            # ignore, db is not set yet, may be set later
          else
            db.extension :date_arithmetic
          end
        end
      end
    end
  end
end
