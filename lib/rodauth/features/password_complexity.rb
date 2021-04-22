# frozen-string-literal: true

module Rodauth
  Feature.define(:password_complexity, :PasswordComplexity) do
    depends :login_password_requirements_base

    auth_value_method :password_dictionary_file, nil
    auth_value_method :password_dictionary, nil
    auth_value_method :password_character_groups, [/[a-z]/, /[A-Z]/, /\d/, /[^a-zA-Z\d]/]
    auth_value_method :password_min_groups, 3
    auth_value_method :password_max_length_for_groups_check, 11
    auth_value_method :password_max_repeating_characters, 3
    auth_value_method :password_invalid_pattern, Regexp.union([/qwerty/i, /azerty/i, /asdf/i, /zxcv/i] + (1..8).map{|i| /#{i}#{i+1}#{(i+2)%10}/})
    translatable_method :password_not_enough_character_groups_message, "does not include uppercase letters, lowercase letters, and numbers"
    translatable_method :password_invalid_pattern_message, "includes common character sequence"
    translatable_method :password_in_dictionary_message, "is a word in a dictionary"
    translatable_method :password_too_many_repeating_characters_message, "contains too many of the same character in a row"

    def password_meets_requirements?(password)
      super && \
        password_has_enough_character_groups?(password) && \
        password_has_no_invalid_pattern?(password) && \
        password_not_too_many_repeating_characters?(password) && \
        password_not_in_dictionary?(password)
    end

    def post_configure
      super
      return if method(:password_dictionary).owner != Rodauth::PasswordComplexity

      case password_dictionary_file
      when false
        # nothing
      when nil
        default_dictionary_file = '/usr/share/dict/words'
        # :nocov:
        if File.file?(default_dictionary_file)
        # :nocov:
          words = File.read(default_dictionary_file)
        end
      else
        words = File.read(password_dictionary_file)
      end

      return unless words

      require 'set'
      dict = Set.new(words.downcase.split)
      self.class.send(:define_method, :password_dictionary){dict}
    end

    private

    def password_has_enough_character_groups?(password)
      return true if password.length > password_max_length_for_groups_check
      return true if password_character_groups.select{|re| password =~ re}.length >= password_min_groups
      set_password_requirement_error_message(:not_enough_character_groups_in_password, password_not_enough_character_groups_message)
      false
    end

    def password_has_no_invalid_pattern?(password)
      return true unless password_invalid_pattern
      return true if password !~ password_invalid_pattern
      set_password_requirement_error_message(:invalid_password_pattern, password_invalid_pattern_message)
      false
    end

    def password_not_too_many_repeating_characters?(password)
      return true if password_max_repeating_characters < 2
      return true if password !~ /(.)(\1){#{password_max_repeating_characters-1}}/ 
      set_password_requirement_error_message(:too_many_repeating_characters_in_password, password_too_many_repeating_characters_message)
      false
    end

    def password_not_in_dictionary?(password)
      return true unless dict = password_dictionary
      return true unless password =~ /\A(?:\d*)([A-Za-z!@$+|][A-Za-z!@$+|0134578]+[A-Za-z!@$+|])(?:\d*)\z/
      word = $1.downcase.tr('!@$+|0134578', 'iastloleastb')
      return true if !dict.include?(word)
      set_password_requirement_error_message(:password_in_dictionary, password_in_dictionary_message)
      false
    end
  end
end
