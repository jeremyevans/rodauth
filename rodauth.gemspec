spec = Gem::Specification.new do |s|
  s.name = 'rodauth'
  s.version = '0.1.0'
  s.platform = Gem::Platform::RUBY
  s.has_rdoc = true
  s.extra_rdoc_files = ["README.rdoc", "CHANGELOG", "MIT-LICENSE"]
  s.rdoc_options += ["--quiet", "--line-numbers", "--inline-source", '--title', 'Rodauth: Authentication Framework for Roda/Sequel/PostgreSQL', '--main', 'README.rdoc']
  s.license = "MIT"
  s.summary = "Authentication Framework for Roda/Sequel/PostgreSQL"
  s.author = "Jeremy Evans"
  s.email = "code@jeremyevans.net"
  s.homepage = "https://github.com/jeremyevans/rodauth"
  s.files = %w(MIT-LICENSE CHANGELOG README.rdoc Rakefile) + Dir["{spec,lib}/**/*.rb"] + Dir["templates/*.str"]
  s.description = <<END
Rodauth is an authorization framework using Roda, Sequel, and PostgreSQL.
It aims to provide strong security for password storage by utilizing
separate PostgreSQL database accounts.  Configuration is done via
a DSL that makes it easy to override any part of the authentication
process.

Rodauth currently supports the following authentication-related
features: login, logout, change password, change login, reset
password, create account, close account, verify account.
END
  s.add_dependency('sequel', [">= 4"])
  s.add_dependency('roda', [">= 2"])
  s.add_development_dependency "minitest", '>=5.0.0'
  s.add_development_dependency "minitest-hooks", '>=1.1.0'
  s.add_development_dependency "capybara", '>=2.1.0'
end
