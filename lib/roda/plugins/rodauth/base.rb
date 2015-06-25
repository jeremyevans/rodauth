class Roda
  module RodaPlugins
    module Rodauth
      Base = Feature.define(:base)
      Base.module_eval do
        auth_value_methods :account_model, :prefix, :session_key, :account_id, :account_status_id, :account_open_status_value
        auth_methods :set_title, :clear_session, :account_from_session

        attr_reader :scope

        def initialize(scope)
          @scope = scope
        end

        def features
          self.class.features
        end

        def request
          scope.request
        end

        def response
          scope.response
        end

        def session
          scope.session
        end

        def wrap(obj)
          if obj
            self.class.wrapper.new(self, obj)
          end
        end

        # Overridable methods

        def account_model
          ::Account
        end

        def clear_session(session)
          session.clear
        end

        def prefix
          ''
        end

        def set_title(title)
        end

        def session_key
          :account_id
        end

        def account_id
          :id
        end

        def account_status_id
          :status_id
        end

        def account_open_status_value
          2
        end

        def account_from_session
          account_model.where(account_status_id=>account_open_status_value, account_id=>scope.session[session_key]).first
        end

        def view(page, title)
          set_title(title)
          scope.instance_exec do
            template_opts = find_template(parse_template_opts(page, {}))
            unless File.file?(template_path(template_opts))
              template_opts[:path] = File.join(File.dirname(__FILE__), '../../../../templates', "#{page}.str")
            end
            view(template_opts)
          end
        end
      end
    end
  end
end
