# frozen-string-literal: true

module Rodauth
  Feature.define(:remember, :Remember) do
    notice_flash "Your remember setting has been updated"
    error_flash "There was an error updating your remember setting"
    loaded_templates %w'remember'
    view 'remember', 'Change Remember Setting'
    additional_form_tags
    button 'Change Remember Setting'
    before
    before 'load_memory'
    after
    after 'load_memory'
    redirect

    auth_value_method :raw_remember_token_deadline, nil
    auth_value_method :remember_cookie_options, {}.freeze
    auth_value_method :extend_remember_deadline?, false
    auth_value_method :remember_period, {:days=>14}.freeze
    auth_value_method :remember_deadline_interval, {:days=>14}.freeze
    auth_value_method :remember_id_column, :id
    auth_value_method :remember_key_column, :key
    auth_value_method :remember_deadline_column, :deadline
    auth_value_method :remember_table, :account_remember_keys
    auth_value_method :remember_cookie_key, '_remember'
    auth_value_method :remember_param, 'remember'
    auth_value_method :remember_remember_param_value, 'remember'
    auth_value_method :remember_forget_param_value, 'forget'
    auth_value_method :remember_disable_param_value, 'disable'
    translatable_method :remember_remember_label, 'Remember Me'
    translatable_method :remember_forget_label, 'Forget Me'
    translatable_method :remember_disable_label, 'Disable Remember Me'

    auth_methods(
      :add_remember_key,
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

    route do |r|
      require_account
      before_remember_route

      r.get do
        remember_view
      end

      r.post do
        remember = param(remember_param)
        if [remember_remember_param_value, remember_forget_param_value, remember_disable_param_value].include?(remember)
          transaction do
            before_remember
            # :nocov:
            case remember
            # :nocov:
            when remember_remember_param_value
              remember_login
            when remember_forget_param_value
              forget_login 
            when remember_disable_param_value
              disable_remember_login 
            end
            after_remember
          end

          set_notice_flash remember_notice_flash
          redirect remember_redirect
        else
          set_response_error_status(invalid_field_error_status)
          set_error_flash remember_error_flash
          remember_view
        end
      end
    end

    def load_memory
      return if session[session_key]
      return unless cookie = request.cookies[remember_cookie_key]
      id, key = cookie.split('_', 2)
      return unless id && key

      actual, deadline = active_remember_key_ds(id).get([remember_key_column, remember_deadline_column])
      unless actual
        forget_login
        return
      end

      if hmac_secret
        unless valid = timing_safe_eql?(key, compute_hmac(actual))
          unless raw_remember_token_deadline && raw_remember_token_deadline > convert_timestamp(deadline)
            forget_login
            return
          end
        end
      end

      unless valid || timing_safe_eql?(key, actual)
        forget_login
        return
      end

      set_session_value(session_key, id)
      account = account_from_session
      remove_session_value(session_key)

      unless account
        remove_remember_key(id)
        forget_login
        return 
      end

      before_load_memory
      login_session('remember')

      if extend_remember_deadline?
        active_remember_key_ds(id).update(remember_deadline_column=>Sequel.date_add(Sequel::CURRENT_TIMESTAMP, remember_period))
        remember_login
      end
      after_load_memory
    end

    def remember_login
      get_remember_key
      opts = Hash[remember_cookie_options]
      opts[:value] = "#{account_id}_#{convert_token_key(remember_key_value)}"
      opts[:expires] = convert_timestamp(active_remember_key_ds.get(remember_deadline_column))
      opts[:path] = "/" unless opts.key?(:path)
      opts[:httponly] = true unless opts.key?(:httponly)
      opts[:secure] = true unless opts.key?(:secure) || !request.ssl?
      ::Rack::Utils.set_cookie_header!(response.headers, remember_cookie_key, opts)
    end

    def forget_login
      opts = Hash[remember_cookie_options]
      opts[:path] = "/" unless opts.key?(:path)
      ::Rack::Utils.delete_cookie_header!(response.headers, remember_cookie_key, opts)
    end

    def get_remember_key
      unless @remember_key_value = active_remember_key_ds.get(remember_key_column)
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
      hash = {remember_id_column=>account_id, remember_key_column=>remember_key_value}
      set_deadline_value(hash, remember_deadline_column, remember_deadline_interval)

      if e = raised_uniqueness_violation{remember_key_ds.insert(hash)}
        # If inserting into the remember key table causes a violation, we can pull the 
        # existing row from the table.  If there is no invalid row, we can then reraise.
        raise e unless @remember_key_value = active_remember_key_ds.get(remember_key_column)
      end
    end

    def remove_remember_key(id=account_id)
      remember_key_ds(id).delete
    end

    def logged_in_via_remember_key?
      authenticated_by.include?('remember')
    end

    private

    def after_logout
      forget_login
      super if defined?(super)
    end

    def after_close_account
      remove_remember_key
      super if defined?(super)
    end

    attr_reader :remember_key_value

    def generate_remember_key_value
      @remember_key_value = random_key
    end

    def use_date_arithmetic?
      super || extend_remember_deadline? || db.database_type == :mysql
    end

    def remember_key_ds(id=account_id)
      db[remember_table].where(remember_id_column=>id)
    end

    def active_remember_key_ds(id=account_id)
      remember_key_ds(id).where(Sequel.expr(remember_deadline_column) > Sequel::CURRENT_TIMESTAMP)
    end
  end
end
