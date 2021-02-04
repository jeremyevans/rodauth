require File.expand_path("../lib/rodauth/version", __FILE__)

Gem::Specification.new do |s|
  s.name = 'rodauth'
  s.version = Rodauth.version
  s.platform = Gem::Platform::RUBY
  s.extra_rdoc_files = ["README.rdoc", "CHANGELOG", "MIT-LICENSE"] + Dir["doc/*.rdoc"] + Dir['doc/release_notes/*.txt']
  s.rdoc_options += ["--quiet", "--line-numbers", "--inline-source", '--title', "Rodauth: Ruby's Most Advanced Authentication Framework", '--main', 'README.rdoc']
  s.license = "MIT"
  s.summary = "Authentication and Account Management Framework for Rack Applications"
  s.author = "Jeremy Evans"
  s.email = "code@jeremyevans.net"
  s.homepage = "https://github.com/jeremyevans/rodauth"
  s.required_ruby_version = ">= 1.9.2"
  s.files = %w(MIT-LICENSE CHANGELOG README.rdoc) + Dir["dict/*.txt"] + Dir["doc/**/*.rdoc"] + Dir['doc/release_notes/*.txt'] + Dir["lib/**/*.rb"] + Dir["templates/*.str"] + Dir["javascript/*.js"]
  s.metadata = {
    'bug_tracker_uri'   => 'https://github.com/jeremyevans/rodauth/issues',
    'changelog_uri'     => 'http://rodauth.jeremyevans.net/rdoc/files/CHANGELOG.html',
    'documentation_uri' => 'http://rodauth.jeremyevans.net/documentation.html',
    'mailing_list_uri'  => 'https://groups.google.com/forum/#!forum/rodauth',
    'source_code_uri'   => 'https://github.com/jeremyevans/rodauth',
  }
  s.description = <<END
Rodauth is Ruby's most advanced authentication framework, designed
to work in all rack applications.  It's built using Roda and Sequel,
but it can be used as middleware in front of web applications that use
other web frameworks and database libraries.

Rodauth aims to provide strong security for password storage by
utilizing separate database accounts if possible on PostgreSQL,
MySQL, and Microsoft SQL Server.  Configuration is done via
a DSL that makes it easy to override any part of the authentication
process.

Rodauth supports typical authentication features: such as login and
logout, changing logins and passwords, and creating, verifying,
unlocking, and resetting passwords for accounts.  Rodauth also
supports many advanced authentication features:

* Secure password storage using security definer database functions
* Multiple primary multifactor authentication methods (WebAuthn and
  TOTP), as well as backup multifactor authentication methods (SMS
  and recovery codes).
* Passwordless authentication using email links and WebAuthn
  authenticators.
* Both standard HTML form and JSON API support for all features.
END
  s.add_dependency('sequel', [">= 4"])
  s.add_dependency('roda', [">= 2.6.0"])
  s.add_development_dependency('tilt')
  s.add_development_dependency('rack_csrf')
  s.add_development_dependency('bcrypt')
  s.add_development_dependency('argon2', '>=2')
  s.add_development_dependency('mail')
  s.add_development_dependency('rotp')
  s.add_development_dependency('rqrcode')
  s.add_development_dependency('jwt')
  s.add_development_dependency('webauthn', '>=2')
  s.add_development_dependency("minitest", '>=5.0.0')
  s.add_development_dependency("minitest-global_expectations")
  s.add_development_dependency("minitest-hooks", '>=1.1.0')
  s.add_development_dependency("capybara", '>=2.1.0')
end
