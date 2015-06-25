class Roda
  module RodaPlugins
    module Rodauth
      Base = Feature.define(:base)
      Base.module_eval do
        auth_value_methods :prefix
        auth_methods :set_title, :clear_session

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

        def wrap(obj)
          if obj
            self.class.wrapper.new(self, obj)
          end
        end

        # Overridable methods

        def clear_session(session)
          session.clear
        end

        def prefix
          ''
        end

        def set_title(title)
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
