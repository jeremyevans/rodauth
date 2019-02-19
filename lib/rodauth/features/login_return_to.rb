# frozen-string-literal: true

module Rodauth
  Feature.define(:login_return_to, :LoginReturnTo) do
    depends :base, :login

    auth_value_method :login_return_to_session_key, 'return_to'

    def login_required
      session[login_return_to_session_key] = request.fullpath
      super
    end

    def clear_session
      return_to = session[login_return_to_session_key]
      super
      session[login_return_to_session_key] = return_to
    end

    def login_redirect
      return_to = scope.session.delete(login_return_to_session_key)
      return_to || super
    end

  end
end
