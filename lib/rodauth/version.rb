# frozen-string-literal: true

module Rodauth
  # The major version of Rodauth, updated only for major changes that are
  # likely to require modification to apps using Rodauth.
  MAJOR = 2

  # The minor version of Rodauth, updated for new feature releases of Rodauth.
  MINOR = 39

  # The patch version of Rodauth, updated only for bug fixes from the last
  # feature release.
  TINY = 0

  # The full version of Rodauth as a string
  VERSION = "#{MAJOR}.#{MINOR}.#{TINY}".freeze

  # The full version of Rodauth as a number (1.17.0 => 11700)
  VERSION_NUMBER = MAJOR*10000 + MINOR*100 + TINY

  def self.version
    VERSION
  end
end
