# frozen-string-literal: true

module Rodauth
  Feature.define(:path_class_methods, :PathClassMethods) do
    def post_configure
      super

      klass = self.class
      klass.features.each do |feature_name|
        feature = FEATURES[feature_name]
        feature.routes.each do |handle_meth|
          route = handle_meth.to_s.sub(/\Ahandle_/, '')
          path_meth = :"#{route}_path"
          url_meth = :"#{route}_url"
          instance = klass.allocate.freeze
          klass.define_singleton_method(path_meth){|opts={}| instance.send(path_meth, opts)}
          klass.define_singleton_method(url_meth){|opts={}| instance.send(url_meth, opts)}
        end
      end
    end
  end
end
