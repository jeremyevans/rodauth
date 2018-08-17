$:.unshift(::File.expand_path('../../lib',  __FILE__))
require ::File.expand_path('../rodauth_demo',  __FILE__)
run RodauthDemo::App.app
