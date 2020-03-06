# frozen-string-literal: true

require_relative '../../rodauth'

Roda::RodaPlugins.register_plugin(:rodauth, Rodauth)
