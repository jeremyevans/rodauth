require File.expand_path("../lib/rodauth/version", __FILE__)

Gem::Specification.new do |s|
  s.name = 'rodauth'
  s.version = Rodauth.version
  s.platform = Gem::Platform::RUBY
  s.has_rdoc = true
  s.extra_rdoc_files = ["README.rdoc", "CHANGELOG", "MIT-LICENSE"]
  s.rdoc_options += ["--quiet", "--line-numbers", "--inline-source", '--title', 'Rodauth: Authentication and Account Management Framework for Rack Applications', '--main', 'README.rdoc']
  s.license = "MIT"
  s.summary = "Authentication Framework for Roda/Sequel/PostgreSQL"
  s.author = "Jeremy Evans"
  s.email = "code@jeremyevans.net"
  s.homepage = "https://github.com/jeremyevans/rodauth"
  s.files = %w(MIT-LICENSE CHANGELOG README.rdoc Rakefile) + Dir["{spec,lib}/**/*.rb"] + Dir["{templates,spec/views}/*.str"]
  s.description = <<END
Rodauth is an authentication and account management framework for
rack applications.  It's built using Roda, Sequel, and PostgreSQL,
but it can be used with other web frameworks, database libraries,
and databases.

Rodauth aims to provide strong security for password storage by
utilizing separate database accounts.  Configuration is done via
a DSL that makes it easy to override any part of the authentication
process.

Rodauth currently supports the following authentication-related
features: login, logout, change password, change login, reset
password, create account, close account, verify account, remember,
and lockout.
END
  s.add_dependency('sequel', [">= 4"])
  s.add_dependency('roda', [">= 2"])
  s.add_dependency('tilt')
  s.add_dependency('rack_csrf')
  s.add_dependency('bcrypt')
  s.add_dependency('mail')
  s.add_dependency('rotp')
  s.add_dependency('rqrcode')
  s.add_development_dependency("minitest", '>=5.0.0')
  s.add_development_dependency("minitest-hooks", '>=1.1.0')
  s.add_development_dependency("capybara", '>=2.1.0')
end
